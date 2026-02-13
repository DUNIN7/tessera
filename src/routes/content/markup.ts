// =============================================================================
// TESSERA — Markup Routes
//
// Content-layer routes for the markup engine.
// Mounted at /api/content/markup/* from the content router.
//
// Routes:
//   POST   /sessions                     — Create markup session
//   GET    /sessions/:id                 — Get session state
//   PATCH  /sessions/:id/active-set      — Switch active content set
//   POST   /sessions/:id/operations      — Execute markup operation
//   POST   /sessions/:id/undo            — Undo last operation
//   POST   /sessions/:id/redo            — Redo last undone operation
//   POST   /sessions/:id/pattern         — Apply pattern across document
//   POST   /sessions/:id/propagate       — Propagate term
//   GET    /sessions/:id/overlaps        — Get overlap report
//   POST   /sessions/:id/submit          — Submit for review
//   POST   /sessions/:id/suggestions/generate — Generate AI suggestions
//   GET    /sessions/:id/suggestions     — List suggestions
//   PATCH  /sessions/:id/suggestions/:sid — Resolve a suggestion
//   POST   /sessions/:id/coded-content-check — Check coded content risk
//   GET    /sessions/:id/review-package  — Get review package
//   POST   /sessions/:id/review          — Record review decision
//   POST   /reviews/:id/escalation       — Resolve escalation (admin)
// =============================================================================

import { Router, Response } from 'express';
import { requireRole } from '../../middleware/role-guard';
import { AuthenticatedRequest } from '../../types/auth';
import {
  createMarkupSession,
  getSessionState,
  switchActiveContentSet,
  executeOperation,
  undoOperation,
  redoOperation,
  generateOverlapReport,
  applyPattern,
  propagateSelection,
  submitForReview,
  getReviewPackage,
  recordReviewDecision,
  resolveEscalation,
  generateSuggestions,
  checkCodedContentRisk,
  resolveSuggestion,
  listSuggestions,
} from '../../services/markup';

const router = Router();
// Note: authenticate, requireLayer('content'), and enforceTenantIsolation
// are already applied by the parent content router.

// ── Session Lifecycle ──────────────────────────────────────────────────

/**
 * POST /markup/sessions
 * Create a markup session. Redactor only.
 */
router.post(
  '/sessions',
  requireRole('redactor') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { documentId } = req.body;
    if (!documentId) {
      res.status(400).json({ error: 'documentId required' });
      return;
    }

    try {
      const result = await createMarkupSession({
        documentId,
        organizationId: req.user.organizationId,
        redactorId: req.user.id,
      });
      res.status(201).json(result);
    } catch (err: any) {
      const status = err.message.includes('not found') ? 404
        : err.message.includes('status') ? 409
        : err.message.includes('Another redactor') ? 409 : 500;
      res.status(status).json({ error: err.message });
    }
  }
);

/**
 * GET /markup/sessions/:id
 * Get session state with current assignments. Redactor + Reviewer.
 */
router.get(
  '/sessions/:id',
  requireRole('redactor', 'reviewer', 'org_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const state = await getSessionState(req.params.id, req.user.organizationId);
      res.json(state);
    } catch (err: any) {
      res.status(err.message.includes('not found') ? 404 : 500).json({ error: err.message });
    }
  }
);

/**
 * PATCH /markup/sessions/:id/active-set
 * Switch active content set. (§7.1) Redactor only.
 */
router.patch(
  '/sessions/:id/active-set',
  requireRole('redactor') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { contentSetIdentifier } = req.body;
    if (!contentSetIdentifier) {
      res.status(400).json({ error: 'contentSetIdentifier required' });
      return;
    }

    try {
      await switchActiveContentSet(req.params.id, contentSetIdentifier, req.user.organizationId);
      res.json({ activeContentSet: contentSetIdentifier });
    } catch (err: any) {
      res.status(err.message.includes('not found') ? 404 : 500).json({ error: err.message });
    }
  }
);

// ── Operations (assign, unassign, undo, redo) ──────────────────────────

/**
 * POST /markup/sessions/:id/operations
 * Execute a markup operation. Redactor only. (§7.2)
 */
router.post(
  '/sessions/:id/operations',
  requireRole('redactor') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { type, contentSetIdentifier, selections, source, pattern, suggestionId } = req.body;

    if (!type || !contentSetIdentifier || !selections || !Array.isArray(selections)) {
      res.status(400).json({
        error: 'Required: type (assign|unassign|bulk_assign|bulk_unassign), contentSetIdentifier, selections[]',
      });
      return;
    }

    try {
      const result = await executeOperation({
        sessionId: req.params.id,
        organizationId: req.user.organizationId,
        type,
        contentSetIdentifier,
        selections,
        source: source || 'manual',
        pattern,
        suggestionId,
      });

      res.status(201).json({
        ...result,
        overlapWarnings: result.overlaps.length > 0
          ? `${result.overlaps.length} cross-set overlap(s) detected. Review overlap report.`
          : null,
      });
    } catch (err: any) {
      res.status(err.message.includes('not found') ? 404 : 500).json({ error: err.message });
    }
  }
);

/**
 * POST /markup/sessions/:id/undo
 * Undo last operation. (§7.2) Redactor only.
 */
router.post(
  '/sessions/:id/undo',
  requireRole('redactor') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const result = await undoOperation(req.params.id, req.user.organizationId);
      res.json(result.undoneSequence !== null
        ? { undone: true, sequence: result.undoneSequence }
        : { undone: false, message: 'Nothing to undo' });
    } catch (err: any) {
      res.status(err.message.includes('not found') ? 404 : 500).json({ error: err.message });
    }
  }
);

/**
 * POST /markup/sessions/:id/redo
 * Redo last undone operation. (§7.2) Redactor only.
 */
router.post(
  '/sessions/:id/redo',
  requireRole('redactor') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const result = await redoOperation(req.params.id, req.user.organizationId);
      res.json(result.redoneSequence !== null
        ? { redone: true, sequence: result.redoneSequence }
        : { redone: false, message: 'Nothing to redo' });
    } catch (err: any) {
      res.status(err.message.includes('not found') ? 404 : 500).json({ error: err.message });
    }
  }
);

// ── Pattern & Propagation ──────────────────────────────────────────────

/**
 * POST /markup/sessions/:id/pattern
 * Apply a regex pattern across all document blocks. (§7.3) Redactor only.
 */
router.post(
  '/sessions/:id/pattern',
  requireRole('redactor') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { contentSetIdentifier, pattern, documentBlocks } = req.body;

    if (!contentSetIdentifier || !pattern || !documentBlocks) {
      res.status(400).json({ error: 'Required: contentSetIdentifier, pattern, documentBlocks[]' });
      return;
    }

    try {
      const result = await applyPattern({
        sessionId: req.params.id,
        organizationId: req.user.organizationId,
        contentSetIdentifier,
        pattern,
        documentBlocks,
      });
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  }
);

/**
 * POST /markup/sessions/:id/propagate
 * Find all occurrences of a term and assign. (§7.3) Redactor only.
 */
router.post(
  '/sessions/:id/propagate',
  requireRole('redactor') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { contentSetIdentifier, term, documentBlocks } = req.body;

    if (!contentSetIdentifier || !term || !documentBlocks) {
      res.status(400).json({ error: 'Required: contentSetIdentifier, term, documentBlocks[]' });
      return;
    }

    try {
      const result = await propagateSelection({
        sessionId: req.params.id,
        organizationId: req.user.organizationId,
        contentSetIdentifier,
        term,
        documentBlocks,
      });
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  }
);

// ── Overlap Report ─────────────────────────────────────────────────────

/**
 * GET /markup/sessions/:id/overlaps
 * Get cross-set overlap report. (§5.3) Redactor + Reviewer.
 */
router.get(
  '/sessions/:id/overlaps',
  requireRole('redactor', 'reviewer', 'org_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const report = await generateOverlapReport(req.params.id, req.user.organizationId);
      res.json(report);
    } catch (err: any) {
      res.status(err.message.includes('not found') ? 404 : 500).json({ error: err.message });
    }
  }
);

// ── AI Suggestions ─────────────────────────────────────────────────────

/**
 * POST /markup/sessions/:id/suggestions/generate
 * Generate AI redaction suggestions. (§7.3) Redactor only.
 */
router.post(
  '/sessions/:id/suggestions/generate',
  requireRole('redactor') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { documentBlocks } = req.body;
    if (!documentBlocks) {
      res.status(400).json({ error: 'documentBlocks[] required' });
      return;
    }

    try {
      const result = await generateSuggestions({
        sessionId: req.params.id,
        documentBlocks,
      });
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  }
);

/**
 * GET /markup/sessions/:id/suggestions
 * List suggestions with optional filtering. Redactor only.
 */
router.get(
  '/sessions/:id/suggestions',
  requireRole('redactor', 'reviewer') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const suggestions = await listSuggestions({
        sessionId: req.params.id,
        status: req.query.status as any,
        type: req.query.type as any,
        limit: parseInt(req.query.limit as string) || 50,
        offset: parseInt(req.query.offset as string) || 0,
      });
      res.json({ suggestions });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  }
);

/**
 * PATCH /markup/sessions/:id/suggestions/:sid
 * Resolve a suggestion: accept, reject, or dismiss. (§7.3) Redactor only.
 */
router.patch(
  '/sessions/:id/suggestions/:sid',
  requireRole('redactor') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { status } = req.body;
    if (!status || !['accepted', 'rejected', 'dismissed'].includes(status)) {
      res.status(400).json({ error: 'status required: accepted | rejected | dismissed' });
      return;
    }

    try {
      await resolveSuggestion({
        suggestionId: req.params.sid,
        sessionId: req.params.id,
        status,
        resolvedBy: req.user.id,
      });
      res.json({ resolved: true });
    } catch (err: any) {
      res.status(err.message.includes('not found') ? 404 : 500).json({ error: err.message });
    }
  }
);

/**
 * POST /markup/sessions/:id/coded-content-check
 * Check for coded content risks in current markup state. (§7.4) Redactor only.
 */
router.post(
  '/sessions/:id/coded-content-check',
  requireRole('redactor') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { documentBlocks } = req.body;
    if (!documentBlocks) {
      res.status(400).json({ error: 'documentBlocks[] required' });
      return;
    }

    try {
      const result = await checkCodedContentRisk({
        sessionId: req.params.id,
        documentBlocks,
      });
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  }
);

// ── Submission & Review ────────────────────────────────────────────────

/**
 * POST /markup/sessions/:id/submit
 * Submit markup for review. (§8.1) Redactor only.
 */
router.post(
  '/sessions/:id/submit',
  requireRole('redactor') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const result = await submitForReview({
        sessionId: req.params.id,
        organizationId: req.user.organizationId,
        redactorId: req.user.id,
        notes: req.body.notes,
      });
      res.json(result);
    } catch (err: any) {
      const status = err.message.includes('not found') ? 404
        : err.message.includes('Cannot submit') ? 400 : 500;
      res.status(status).json({ error: err.message });
    }
  }
);

/**
 * GET /markup/sessions/:id/review-package
 * Get the review package: assignments, overlaps, stego report. (§8.1)
 * Reviewer + org admin.
 */
router.get(
  '/sessions/:id/review-package',
  requireRole('reviewer', 'org_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const pkg = await getReviewPackage({
        sessionId: req.params.id,
        organizationId: req.user.organizationId,
      });
      res.json(pkg);
    } catch (err: any) {
      res.status(err.message.includes('not found') ? 404 : 500).json({ error: err.message });
    }
  }
);

/**
 * POST /markup/sessions/:id/review
 * Record a review decision. (§8.1) Reviewer only.
 */
router.post(
  '/sessions/:id/review',
  requireRole('reviewer') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { decision, comments, fullCoverageVerified, escalationLevel } = req.body;

    if (!decision || !['approve', 'reject', 'request_changes', 'escalate'].includes(decision)) {
      res.status(400).json({ error: 'decision required: approve | reject | request_changes | escalate' });
      return;
    }

    try {
      const result = await recordReviewDecision({
        sessionId: req.params.id,
        organizationId: req.user.organizationId,
        reviewerId: req.user.id,
        decision,
        comments: comments || '',
        fullCoverageVerified: fullCoverageVerified || false,
        escalationLevel,
      });
      res.json(result);
    } catch (err: any) {
      const status = err.message.includes('not found') ? 404
        : err.message.includes('Cannot approve') ? 400 : 500;
      res.status(status).json({ error: err.message });
    }
  }
);

/**
 * POST /markup/reviews/:id/escalation
 * Resolve an escalated review. (§8.2) Org admin only.
 */
router.post(
  '/reviews/:id/escalation',
  requireRole('org_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { decision, rationale } = req.body;

    if (!decision || !['approve', 'reject'].includes(decision)) {
      res.status(400).json({ error: 'decision required: approve | reject' });
      return;
    }

    if (!rationale) {
      res.status(400).json({ error: 'rationale required for arbitration decisions' });
      return;
    }

    try {
      const result = await resolveEscalation({
        reviewId: req.params.id,
        organizationId: req.user.organizationId,
        adminId: req.user.id,
        decision,
        rationale,
      });
      res.json(result);
    } catch (err: any) {
      res.status(err.message.includes('not found') ? 404 : 500).json({ error: err.message });
    }
  }
);

export default router;
