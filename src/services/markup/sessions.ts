// =============================================================================
// TESSERA — Markup Session Service
//
// Core markup engine: session management, content assignment operations,
// undo/redo history, state materialization, and overlap detection.
// (Tessera v3.1 §7)
//
// Key design:
//   Operations table = HISTORY (undo/redo stack, full audit trail)
//   Content set assignments table = CURRENT STATE (materialized view)
//   Both are maintained in sync after every operation.
//
// "Markup proceeds one content set at a time." (§7.1)
// "Undo/redo with full history within markup session." (§7.2)
// =============================================================================

import { pool } from '../../db/pool';
import { v4 as uuidv4 } from 'uuid';
import { recordAuditEvent } from '../audit';
import { submitForayTransaction } from '../../foray';
import {
  ContentSelection,
  MarkupOperationType,
  OverlapEntry,
  OverlapReport,
} from '../../types/markup';

// ── Session Lifecycle ──────────────────────────────────────────────────

/**
 * Create a new markup session for a document. (§7)
 * Transitions document status from 'intake_cleared' to 'markup'.
 */
export async function createMarkupSession(params: {
  documentId: string;
  organizationId: string;
  redactorId: string;
}): Promise<{ sessionId: string }> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Verify document is ready for markup
    const docResult = await client.query(
      `SELECT status, title FROM documents
       WHERE id = $1 AND organization_id = $2`,
      [params.documentId, params.organizationId]
    );

    if (docResult.rows.length === 0) {
      throw new Error('Document not found');
    }

    const doc = docResult.rows[0];
    const validStatuses = ['intake_cleared', 'markup', 'review_escalated'];
    if (!validStatuses.includes(doc.status)) {
      throw new Error(
        `Document status is "${doc.status}". Markup requires: ${validStatuses.join(', ')}`
      );
    }

    // Check for existing active session on this document
    const existingSession = await client.query(
      `SELECT id, redactor_id FROM markup_sessions
       WHERE document_id = $1 AND status IN ('active', 'paused')`,
      [params.documentId]
    );

    if (existingSession.rows.length > 0) {
      const existing = existingSession.rows[0];
      if (existing.redactor_id !== params.redactorId) {
        throw new Error('Another redactor has an active session on this document');
      }
      // Return existing session
      await client.query('COMMIT');
      return { sessionId: existing.id };
    }

    // Create session
    const sessionId = uuidv4();
    await client.query(
      `INSERT INTO markup_sessions
         (id, document_id, organization_id, redactor_id, status)
       VALUES ($1, $2, $3, $4, 'active')`,
      [sessionId, params.documentId, params.organizationId, params.redactorId]
    );

    // Transition document to markup
    if (doc.status === 'intake_cleared') {
      await client.query(
        `UPDATE documents SET status = 'markup', updated_at = now() WHERE id = $1`,
        [params.documentId]
      );
    }

    await client.query('COMMIT');

    await recordAuditEvent({
      category: 'action',
      eventType: 'markup.session_created',
      description: `Markup session created for "${doc.title}"`,
      organizationId: params.organizationId,
      actorId: params.redactorId,
      actorRole: 'redactor',
      actorLayer: 'content',
      targetType: 'document',
      targetId: params.documentId,
      metadata: { sessionId },
    });

    return { sessionId };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Get markup session state including current assignments and operation count.
 */
export async function getSessionState(
  sessionId: string,
  organizationId: string
) {
  const sessionResult = await pool.query(
    `SELECT ms.*, d.title as document_title, d.normalized_path,
            u.display_name as redactor_name
     FROM markup_sessions ms
     JOIN documents d ON d.id = ms.document_id
     JOIN users u ON u.id = ms.redactor_id
     WHERE ms.id = $1 AND ms.organization_id = $2`,
    [sessionId, organizationId]
  );

  if (sessionResult.rows.length === 0) {
    throw new Error('Session not found');
  }

  const session = sessionResult.rows[0];

  // Current assignments grouped by content set
  const assignments = await pool.query(
    `SELECT content_set_identifier, block_id, start_offset, end_offset,
            selected_text, page_number
     FROM content_set_assignments
     WHERE session_id = $1
     ORDER BY content_set_identifier, page_number, block_id, start_offset`,
    [sessionId]
  );

  // Group by content set
  const assignmentsBySet: Record<string, any[]> = {};
  for (const row of assignments.rows) {
    const set = row.content_set_identifier;
    if (!assignmentsBySet[set]) assignmentsBySet[set] = [];
    assignmentsBySet[set].push(row);
  }

  // Pending suggestions count
  const suggestionsResult = await pool.query(
    `SELECT COUNT(*) as count FROM markup_suggestions
     WHERE session_id = $1 AND status = 'pending'`,
    [sessionId]
  );

  return {
    session,
    assignments: assignmentsBySet,
    totalAssignments: assignments.rows.length,
    pendingSuggestions: parseInt(suggestionsResult.rows[0].count),
  };
}

/**
 * Switch the active content set being marked up. (§7.1)
 * "Markup proceeds one content set at a time."
 */
export async function switchActiveContentSet(
  sessionId: string,
  contentSetIdentifier: string,
  organizationId: string
): Promise<void> {
  const result = await pool.query(
    `UPDATE markup_sessions
     SET active_content_set = $1, updated_at = now()
     WHERE id = $2 AND organization_id = $3 AND status IN ('active', 'revision')
     RETURNING id`,
    [contentSetIdentifier, sessionId, organizationId]
  );

  if (result.rows.length === 0) {
    throw new Error('Session not found or not in an editable state');
  }
}

// ── Markup Operations ──────────────────────────────────────────────────

/**
 * Execute a markup operation: assign or unassign selections to a content set.
 * (Tessera v3.1 §7.2)
 *
 * Handles:
 *   - Sequential numbering within session
 *   - Redo stack truncation (new op after undo discards forward history)
 *   - Materialized state update (content_set_assignments)
 *   - Cross-set overlap warnings (§5.3)
 */
export async function executeOperation(params: {
  sessionId: string;
  organizationId: string;
  type: MarkupOperationType;
  contentSetIdentifier: string;
  selections: ContentSelection[];
  source: 'manual' | 'pattern' | 'propagation' | 'suggestion_accepted';
  pattern?: string;
  suggestionId?: string;
}): Promise<{
  operationId: string;
  sequenceNumber: number;
  overlaps: OverlapEntry[];
}> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Verify session is editable
    const sessionResult = await client.query(
      `SELECT id, operation_count, undo_position
       FROM markup_sessions
       WHERE id = $1 AND organization_id = $2 AND status IN ('active', 'revision')
       FOR UPDATE`,
      [params.sessionId, params.organizationId]
    );

    if (sessionResult.rows.length === 0) {
      throw new Error('Session not found or not in an editable state');
    }

    const session = sessionResult.rows[0];
    const newSequence = session.operation_count + 1;

    // Truncate redo stack: if we're behind the operation count,
    // mark all operations after undo_position as undone (§7.2 undo/redo)
    if (session.undo_position < session.operation_count) {
      await client.query(
        `UPDATE markup_operations
         SET is_undone = true
         WHERE session_id = $1 AND sequence_number > $2 AND is_undone = false`,
        [params.sessionId, session.undo_position]
      );

      // Remove materialized state from truncated operations
      await client.query(
        `DELETE FROM content_set_assignments
         WHERE session_id = $1 AND created_by_operation_id IN (
           SELECT id FROM markup_operations
           WHERE session_id = $1 AND sequence_number > $2
         )`,
        [params.sessionId, session.undo_position]
      );
    }

    // Create the operation
    const operationId = uuidv4();
    await client.query(
      `INSERT INTO markup_operations
         (id, session_id, type, content_set_identifier, sequence_number,
          source, pattern, suggestion_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        operationId, params.sessionId, params.type,
        params.contentSetIdentifier, newSequence,
        params.source, params.pattern || null, params.suggestionId || null,
      ]
    );

    // Insert selections for this operation
    for (const sel of params.selections) {
      await client.query(
        `INSERT INTO markup_selections
           (id, operation_id, block_id, granularity, start_offset,
            end_offset, selected_text, page_number)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [
          uuidv4(), operationId, sel.blockId, sel.granularity,
          sel.startOffset, sel.endOffset, sel.selectedText || null,
          sel.page,
        ]
      );
    }

    // Materialize state: update content_set_assignments
    if (params.type === 'assign' || params.type === 'bulk_assign') {
      for (const sel of params.selections) {
        await client.query(
          `INSERT INTO content_set_assignments
             (id, session_id, content_set_identifier, block_id,
              start_offset, end_offset, selected_text, page_number,
              created_by_operation_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
          [
            uuidv4(), params.sessionId, params.contentSetIdentifier,
            sel.blockId, sel.startOffset, sel.endOffset,
            sel.selectedText || null, sel.page, operationId,
          ]
        );
      }
    } else {
      // Unassign: remove matching assignments
      for (const sel of params.selections) {
        await client.query(
          `DELETE FROM content_set_assignments
           WHERE session_id = $1
             AND content_set_identifier = $2
             AND block_id = $3
             AND COALESCE(start_offset, -1) = COALESCE($4::int, -1)
             AND COALESCE(end_offset, -1) = COALESCE($5::int, -1)`,
          [
            params.sessionId, params.contentSetIdentifier,
            sel.blockId, sel.startOffset, sel.endOffset,
          ]
        );
      }
    }

    // Update session counters
    await client.query(
      `UPDATE markup_sessions
       SET operation_count = $1, undo_position = $1, updated_at = now()
       WHERE id = $2`,
      [newSequence, params.sessionId]
    );

    await client.query('COMMIT');

    // Detect cross-set overlaps for the affected selections (§5.3)
    const overlaps = await detectOverlaps(params.sessionId, params.selections);

    return { operationId, sequenceNumber: newSequence, overlaps };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Undo the last operation. (§7.2)
 */
export async function undoOperation(
  sessionId: string,
  organizationId: string
): Promise<{ undoneSequence: number | null }> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const session = await client.query(
      `SELECT undo_position FROM markup_sessions
       WHERE id = $1 AND organization_id = $2 AND status IN ('active', 'revision')
       FOR UPDATE`,
      [sessionId, organizationId]
    );

    if (session.rows.length === 0) throw new Error('Session not found or not editable');

    const pos = session.rows[0].undo_position;
    if (pos === 0) {
      await client.query('COMMIT');
      return { undoneSequence: null }; // Nothing to undo
    }

    // Mark the operation at current position as undone
    const opResult = await client.query(
      `UPDATE markup_operations
       SET is_undone = true
       WHERE session_id = $1 AND sequence_number = $2
       RETURNING id, type, content_set_identifier`,
      [sessionId, pos]
    );

    if (opResult.rows.length > 0) {
      const op = opResult.rows[0];

      // Reverse the materialized state
      if (op.type === 'assign' || op.type === 'bulk_assign') {
        // Undo assign = remove assignments created by this operation
        await client.query(
          `DELETE FROM content_set_assignments
           WHERE created_by_operation_id = $1`,
          [op.id]
        );
      } else {
        // Undo unassign = re-create assignments from the operation's selections
        const selections = await client.query(
          `SELECT block_id, start_offset, end_offset, selected_text, page_number
           FROM markup_selections WHERE operation_id = $1`,
          [op.id]
        );

        for (const sel of selections.rows) {
          await client.query(
            `INSERT INTO content_set_assignments
               (id, session_id, content_set_identifier, block_id,
                start_offset, end_offset, selected_text, page_number,
                created_by_operation_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
            [
              uuidv4(), sessionId, op.content_set_identifier,
              sel.block_id, sel.start_offset, sel.end_offset,
              sel.selected_text, sel.page_number, op.id,
            ]
          );
        }
      }
    }

    // Decrement undo position
    await client.query(
      `UPDATE markup_sessions SET undo_position = $1, updated_at = now() WHERE id = $2`,
      [pos - 1, sessionId]
    );

    await client.query('COMMIT');
    return { undoneSequence: pos };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Redo a previously undone operation. (§7.2)
 */
export async function redoOperation(
  sessionId: string,
  organizationId: string
): Promise<{ redoneSequence: number | null }> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const session = await client.query(
      `SELECT undo_position, operation_count FROM markup_sessions
       WHERE id = $1 AND organization_id = $2 AND status IN ('active', 'revision')
       FOR UPDATE`,
      [sessionId, organizationId]
    );

    if (session.rows.length === 0) throw new Error('Session not found or not editable');

    const { undo_position: pos, operation_count: total } = session.rows[0];
    const nextSeq = pos + 1;

    if (nextSeq > total) {
      await client.query('COMMIT');
      return { redoneSequence: null }; // Nothing to redo
    }

    // Find the operation at next position
    const opResult = await client.query(
      `SELECT id, type, content_set_identifier FROM markup_operations
       WHERE session_id = $1 AND sequence_number = $2`,
      [sessionId, nextSeq]
    );

    if (opResult.rows.length > 0) {
      const op = opResult.rows[0];

      // Mark as not undone
      await client.query(
        `UPDATE markup_operations SET is_undone = false WHERE id = $1`,
        [op.id]
      );

      // Re-apply materialized state
      if (op.type === 'assign' || op.type === 'bulk_assign') {
        const selections = await client.query(
          `SELECT block_id, start_offset, end_offset, selected_text, page_number
           FROM markup_selections WHERE operation_id = $1`,
          [op.id]
        );

        for (const sel of selections.rows) {
          await client.query(
            `INSERT INTO content_set_assignments
               (id, session_id, content_set_identifier, block_id,
                start_offset, end_offset, selected_text, page_number,
                created_by_operation_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
            [
              uuidv4(), sessionId, op.content_set_identifier,
              sel.block_id, sel.start_offset, sel.end_offset,
              sel.selected_text, sel.page_number, op.id,
            ]
          );
        }
      } else {
        // Redo unassign = remove matching assignments
        await client.query(
          `DELETE FROM content_set_assignments
           WHERE created_by_operation_id = $1`,
          [op.id]
        );
      }
    }

    await client.query(
      `UPDATE markup_sessions SET undo_position = $1, updated_at = now() WHERE id = $2`,
      [nextSeq, sessionId]
    );

    await client.query('COMMIT');
    return { redoneSequence: nextSeq };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ── Overlap Detection ──────────────────────────────────────────────────

/**
 * Detect cross-set overlap for given selections. (§5.3)
 * "Warnings displayed when content assigned to multiple sets,
 *  showing resulting access level visibility."
 */
async function detectOverlaps(
  sessionId: string,
  selections: ContentSelection[]
): Promise<OverlapEntry[]> {
  const overlaps: OverlapEntry[] = [];

  for (const sel of selections) {
    // Find all content sets this block+range appears in
    const result = await pool.query(
      `SELECT DISTINCT content_set_identifier
       FROM content_set_assignments
       WHERE session_id = $1 AND block_id = $2
         AND COALESCE(start_offset, -1) = COALESCE($3::int, -1)
         AND COALESCE(end_offset, -1) = COALESCE($4::int, -1)`,
      [sessionId, sel.blockId, sel.startOffset, sel.endOffset]
    );

    if (result.rows.length > 1) {
      overlaps.push({
        selection: sel,
        contentSets: result.rows.map((r: any) => r.content_set_identifier),
        visibleAtLevels: [], // Populated by caller with access level resolution
      });
    }
  }

  return overlaps;
}

/**
 * Generate the full overlap report for reviewer verification. (§5.3, §8.1)
 * "Approval workflow includes cross-set overlap report for reviewer verification."
 */
export async function generateOverlapReport(
  sessionId: string,
  organizationId: string
): Promise<OverlapReport> {
  // Verify session exists
  const sessionResult = await pool.query(
    `SELECT document_id FROM markup_sessions
     WHERE id = $1 AND organization_id = $2`,
    [sessionId, organizationId]
  );

  if (sessionResult.rows.length === 0) {
    throw new Error('Session not found');
  }

  // Find ALL overlapping selections: same block+range in multiple sets
  const overlapResult = await pool.query(
    `SELECT block_id, start_offset, end_offset, selected_text, page_number,
            array_agg(DISTINCT content_set_identifier) as content_sets
     FROM content_set_assignments
     WHERE session_id = $1
     GROUP BY block_id, start_offset, end_offset, selected_text, page_number
     HAVING COUNT(DISTINCT content_set_identifier) > 1
     ORDER BY page_number, block_id, start_offset`,
    [sessionId]
  );

  const entries: OverlapEntry[] = overlapResult.rows.map((row: any) => ({
    selection: {
      selectionId: '', // Not tracked at this level
      blockId: row.block_id,
      granularity: 'paragraph' as const, // Approximate
      startOffset: row.start_offset,
      endOffset: row.end_offset,
      selectedText: row.selected_text,
      page: row.page_number,
    },
    contentSets: row.content_sets,
    visibleAtLevels: [], // TODO: resolve against access_levels + access_level_content_sets
  }));

  return {
    documentId: sessionResult.rows[0].document_id,
    sessionId,
    overlapCount: entries.length,
    entries,
    generatedAt: new Date().toISOString(),
  };
}

// ── Pattern-Based Redaction ────────────────────────────────────────────

/**
 * Apply a pattern across the entire document and assign all matches
 * to a content set. (§7.3: "redactor specifies patterns; system
 * applies across entire document")
 *
 * Returns the operation result with overlap warnings.
 */
export async function applyPattern(params: {
  sessionId: string;
  organizationId: string;
  contentSetIdentifier: string;
  pattern: string;
  documentBlocks: Array<{ blockId: string; text: string; page: number }>;
}): Promise<{
  operationId: string;
  matchCount: number;
  overlaps: OverlapEntry[];
}> {
  const regex = new RegExp(params.pattern, 'gi');
  const selections: ContentSelection[] = [];

  for (const block of params.documentBlocks) {
    let match;
    while ((match = regex.exec(block.text)) !== null) {
      selections.push({
        selectionId: uuidv4(),
        blockId: block.blockId,
        granularity: 'word',
        startOffset: match.index,
        endOffset: match.index + match[0].length,
        selectedText: match[0],
        page: block.page,
      });
    }
  }

  if (selections.length === 0) {
    return { operationId: '', matchCount: 0, overlaps: [] };
  }

  const result = await executeOperation({
    sessionId: params.sessionId,
    organizationId: params.organizationId,
    type: 'bulk_assign',
    contentSetIdentifier: params.contentSetIdentifier,
    selections,
    source: 'pattern',
    pattern: params.pattern,
  });

  return {
    operationId: result.operationId,
    matchCount: selections.length,
    overlaps: result.overlaps,
  };
}

/**
 * Propagate: find all occurrences of selected text and assign them
 * to the same content set. (§7.3: "auto-highlight all occurrences
 * of a selected term")
 */
export async function propagateSelection(params: {
  sessionId: string;
  organizationId: string;
  contentSetIdentifier: string;
  term: string;
  documentBlocks: Array<{ blockId: string; text: string; page: number }>;
}): Promise<{
  operationId: string;
  matchCount: number;
  overlaps: OverlapEntry[];
}> {
  // Escape regex special characters for literal match
  const escaped = params.term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return applyPattern({
    ...params,
    pattern: `\\b${escaped}\\b`,
  });
}
