// =============================================================================
// TESSERA — Approval Workflow Service
//
// Markup submission for review, reviewer decisions, and escalation path.
// (Tessera v3.1 §8.1, §8.2)
//
// Workflow:
//   1. Redactor submits markup → document status 'markup_submitted'
//   2. Reviewer examines: visual overlay, overlap report, stego report
//   3. Decision: approve → 'approved', reject/request_changes → 'markup',
//      escalate → 'review_escalated'
//   4. Approve triggers transition to deconstruction (Phase 4)
//
// "Reviewer must have visibility into all content sets." (§8.1)
// "All escalation details and resolutions recorded on blockchain." (§8.2)
// =============================================================================

import { pool } from '../../db/pool';
import { v4 as uuidv4 } from 'uuid';
import { recordAuditEvent } from '../audit';
import { submitForayTransaction } from '../../foray';
import { generateOverlapReport } from './sessions';
import { ReviewDecision, EscalationLevel } from '../../types/markup';

/**
 * Submit markup for review. (§8.1)
 * Transitions: session → 'submitted', document → 'markup_submitted'
 */
export async function submitForReview(params: {
  sessionId: string;
  organizationId: string;
  redactorId: string;
  notes?: string;
}): Promise<{ submitted: boolean }> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Verify session is active and belongs to this redactor
    const sessionResult = await client.query(
      `SELECT ms.id, ms.document_id, d.title, ms.operation_count
       FROM markup_sessions ms
       JOIN documents d ON d.id = ms.document_id
       WHERE ms.id = $1 AND ms.organization_id = $2
         AND ms.redactor_id = $3
         AND ms.status IN ('active', 'revision')
       FOR UPDATE`,
      [params.sessionId, params.organizationId, params.redactorId]
    );

    if (sessionResult.rows.length === 0) {
      throw new Error('Session not found or not in a submittable state');
    }

    const session = sessionResult.rows[0];

    if (session.operation_count === 0) {
      throw new Error('Cannot submit session with no markup operations');
    }

    // Verify at least one content set has assignments
    const assignmentCheck = await client.query(
      `SELECT COUNT(DISTINCT content_set_identifier) as set_count
       FROM content_set_assignments WHERE session_id = $1`,
      [params.sessionId]
    );

    if (parseInt(assignmentCheck.rows[0].set_count) === 0) {
      throw new Error('Cannot submit: no content assigned to any content set');
    }

    // Transition session and document
    await client.query(
      `UPDATE markup_sessions
       SET status = 'submitted', notes = COALESCE($1, notes), updated_at = now()
       WHERE id = $2`,
      [params.notes, params.sessionId]
    );

    await client.query(
      `UPDATE documents SET status = 'markup_submitted', updated_at = now()
       WHERE id = $1`,
      [session.document_id]
    );

    await client.query('COMMIT');

    // Audit
    await recordAuditEvent({
      category: 'action',
      eventType: 'markup.submitted',
      description: `Markup submitted for review: "${session.title}"`,
      organizationId: params.organizationId,
      actorId: params.redactorId,
      actorRole: 'redactor',
      actorLayer: 'content',
      targetType: 'document',
      targetId: session.document_id,
      metadata: {
        sessionId: params.sessionId,
        operationCount: session.operation_count,
      },
    });

    return { submitted: true };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Get the review package for a submitted markup session. (§8.1)
 * Includes: markup summary, overlap report, stego scan report.
 *
 * "Reviewer examines content-to-set assignments using visual overlay.
 *  Reviewer verifies cross-set overlap is intentional.
 *  Reviewer examines flagged steganographic/encoding anomalies."
 */
export async function getReviewPackage(params: {
  sessionId: string;
  organizationId: string;
}) {
  // Session with document info
  const sessionResult = await pool.query(
    `SELECT ms.*, d.title, d.stego_scan_result, d.original_hash,
            d.normalized_hash, u.display_name as redactor_name
     FROM markup_sessions ms
     JOIN documents d ON d.id = ms.document_id
     JOIN users u ON u.id = ms.redactor_id
     WHERE ms.id = $1 AND ms.organization_id = $2`,
    [params.sessionId, params.organizationId]
  );

  if (sessionResult.rows.length === 0) {
    throw new Error('Session not found');
  }

  const session = sessionResult.rows[0];

  // Content set assignments summary
  const assignmentSummary = await pool.query(
    `SELECT content_set_identifier,
            COUNT(*) as selection_count,
            COUNT(DISTINCT block_id) as block_count,
            COUNT(DISTINCT page_number) as page_count
     FROM content_set_assignments
     WHERE session_id = $1
     GROUP BY content_set_identifier
     ORDER BY content_set_identifier`,
    [params.sessionId]
  );

  // Overlap report (§5.3, §8.1)
  const overlapReport = await generateOverlapReport(
    params.sessionId, params.organizationId
  );

  // Stego scan report (§8.1 step 3)
  const stegoReport = session.stego_scan_result || null;

  // Previous reviews for this session (for revision cycles)
  const previousReviews = await pool.query(
    `SELECT r.*, u.display_name as reviewer_name
     FROM markup_reviews r
     JOIN users u ON u.id = r.reviewer_id
     WHERE r.session_id = $1
     ORDER BY r.created_at DESC`,
    [params.sessionId]
  );

  // Suggestion summary
  const suggestionSummary = await pool.query(
    `SELECT type, status, COUNT(*) as count
     FROM markup_suggestions
     WHERE session_id = $1
     GROUP BY type, status
     ORDER BY type`,
    [params.sessionId]
  );

  return {
    session: {
      id: session.id,
      documentId: session.document_id,
      documentTitle: session.title,
      redactorName: session.redactor_name,
      status: session.status,
      operationCount: session.operation_count,
      notes: session.notes,
    },
    assignmentSummary: assignmentSummary.rows,
    overlapReport,
    stegoReport,
    previousReviews: previousReviews.rows,
    suggestionSummary: suggestionSummary.rows,
  };
}

/**
 * Record a review decision. (§8.1, §8.2)
 *
 * Approve → session 'approved', document 'approved' (ready for deconstruction)
 * Reject → session back to 'revision', document back to 'markup'
 * Request changes → same as reject but softer intent
 * Escalate → session stays, document 'review_escalated'
 */
export async function recordReviewDecision(params: {
  sessionId: string;
  organizationId: string;
  reviewerId: string;
  decision: ReviewDecision;
  comments: string;
  fullCoverageVerified: boolean;
  escalationLevel?: EscalationLevel;
}): Promise<{ reviewId: string; newDocumentStatus: string }> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Verify session is submitted/in review
    const sessionResult = await client.query(
      `SELECT ms.id, ms.document_id, d.title
       FROM markup_sessions ms
       JOIN documents d ON d.id = ms.document_id
       WHERE ms.id = $1 AND ms.organization_id = $2
         AND ms.status IN ('submitted', 'approved')
       FOR UPDATE`,
      [params.sessionId, params.organizationId]
    );

    if (sessionResult.rows.length === 0) {
      throw new Error('Session not found or not in a reviewable state');
    }

    const session = sessionResult.rows[0];

    // Enforce full coverage requirement (§8.1)
    if (params.decision === 'approve' && !params.fullCoverageVerified) {
      throw new Error(
        'Cannot approve: reviewer must verify visibility into all content sets (§8.1)'
      );
    }

    // Determine new statuses
    let newSessionStatus: string;
    let newDocumentStatus: string;

    switch (params.decision) {
      case 'approve':
        newSessionStatus = 'approved';
        newDocumentStatus = 'approved';
        break;
      case 'reject':
      case 'request_changes':
        newSessionStatus = 'revision';
        newDocumentStatus = 'markup';
        break;
      case 'escalate':
        newSessionStatus = 'submitted'; // Stays submitted during escalation
        newDocumentStatus = 'review_escalated';
        break;
      default:
        throw new Error(`Invalid decision: ${params.decision}`);
    }

    // Create review record
    const reviewId = uuidv4();
    await client.query(
      `INSERT INTO markup_reviews
         (id, session_id, document_id, organization_id, reviewer_id,
          decision, comments, full_coverage_verified, escalation_level)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        reviewId, params.sessionId, session.document_id,
        params.organizationId, params.reviewerId,
        params.decision, params.comments,
        params.fullCoverageVerified,
        params.escalationLevel || null,
      ]
    );

    // Update session and document status
    await client.query(
      `UPDATE markup_sessions SET status = $1, updated_at = now() WHERE id = $2`,
      [newSessionStatus, params.sessionId]
    );

    await client.query(
      `UPDATE documents SET status = $1, updated_at = now() WHERE id = $2`,
      [newDocumentStatus, session.document_id]
    );

    await client.query('COMMIT');

    // Audit (§8.2: "All escalation details and resolutions recorded on blockchain")
    await recordAuditEvent({
      category: 'action',
      eventType: `markup.review_${params.decision}`,
      description: `Markup reviewed: "${session.title}" — ${params.decision}`,
      organizationId: params.organizationId,
      actorId: params.reviewerId,
      actorRole: 'reviewer',
      actorLayer: 'content',
      targetType: 'document',
      targetId: session.document_id,
      metadata: {
        sessionId: params.sessionId,
        reviewId,
        decision: params.decision,
        fullCoverageVerified: params.fullCoverageVerified,
        escalationLevel: params.escalationLevel,
        comments: params.comments,
      },
    });

    // FORAY transaction for review event
    await submitForayTransaction({
      transactionId: `TESSERA_REVIEW_${reviewId}`,
      transactionType: 'markup_review',
      action: {
        reviewId,
        sessionId: params.sessionId,
        documentId: session.document_id,
        decision: params.decision,
        reviewerId: params.reviewerId,
        escalationLevel: params.escalationLevel,
        timestamp: new Date().toISOString(),
      },
    });

    return { reviewId, newDocumentStatus };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Org admin arbitration for escalated review. (§8.2 step 2)
 * "Admin reviews markup, comments, and rationale; issues binding decision."
 */
export async function resolveEscalation(params: {
  reviewId: string;
  organizationId: string;
  adminId: string;
  decision: 'approve' | 'reject';
  rationale: string;
}): Promise<{ newDocumentStatus: string }> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Find the escalated review
    const reviewResult = await client.query(
      `SELECT r.id, r.session_id, r.document_id, d.title
       FROM markup_reviews r
       JOIN documents d ON d.id = r.document_id
       WHERE r.id = $1 AND r.organization_id = $2 AND r.decision = 'escalate'
       FOR UPDATE`,
      [params.reviewId, params.organizationId]
    );

    if (reviewResult.rows.length === 0) {
      throw new Error('Escalated review not found');
    }

    const review = reviewResult.rows[0];

    // Record arbitration on the review
    await client.query(
      `UPDATE markup_reviews
       SET arbitration_decision = $1, arbitration_by = $2, arbitration_at = now()
       WHERE id = $3`,
      [params.rationale, params.adminId, params.reviewId]
    );

    // Determine outcomes
    let newSessionStatus: string;
    let newDocumentStatus: string;

    if (params.decision === 'approve') {
      newSessionStatus = 'approved';
      newDocumentStatus = 'approved';
    } else {
      newSessionStatus = 'revision';
      newDocumentStatus = 'markup';
    }

    await client.query(
      `UPDATE markup_sessions SET status = $1, updated_at = now() WHERE id = $2`,
      [newSessionStatus, review.session_id]
    );

    await client.query(
      `UPDATE documents SET status = $1, updated_at = now() WHERE id = $2`,
      [newDocumentStatus, review.document_id]
    );

    await client.query('COMMIT');

    // Audit (§8.2: "All escalation details and resolutions recorded on blockchain")
    await recordAuditEvent({
      category: 'action',
      eventType: 'markup.escalation_resolved',
      description: `Escalation resolved by admin for "${review.title}": ${params.decision}`,
      organizationId: params.organizationId,
      actorId: params.adminId,
      actorRole: 'org_admin',
      actorLayer: 'content',
      targetType: 'document',
      targetId: review.document_id,
      metadata: {
        reviewId: params.reviewId,
        adminDecision: params.decision,
        rationale: params.rationale,
      },
    });

    await submitForayTransaction({
      transactionId: `TESSERA_ARBITRATION_${params.reviewId}`,
      transactionType: 'escalation_arbitration',
      action: {
        reviewId: params.reviewId,
        documentId: review.document_id,
        adminId: params.adminId,
        decision: params.decision,
        rationale: params.rationale,
        timestamp: new Date().toISOString(),
      },
    });

    return { newDocumentStatus };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}
