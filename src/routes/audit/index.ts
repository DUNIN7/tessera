// =============================================================================
// TESSERA — Audit Routes
//
// Read-only access to the audit trail. (Tessera v3.1 §11)
// Auditors can query events, verify blockchain anchoring, and
// generate integrity reports.
//
// Note: Auditors have NO access to decrypted document content. (§4)
// They see event metadata, hashes, and FORAY transaction references.
// =============================================================================

import { Router, Response } from 'express';
import { authenticate } from '../../middleware/authenticate';
import { requireRole } from '../../middleware/role-guard';
import { enforceTenantIsolation } from '../../middleware/tenant-isolation';
import { AuthenticatedRequest } from '../../types/auth';
import { queryAuditEvents } from '../../services/audit';

const router = Router();

router.use(authenticate as any);
router.use(enforceTenantIsolation as any);

/**
 * GET /api/audit/events
 * Query audit events with optional filters.
 * Available to auditor and org_admin roles.
 *
 * Query params:
 *   category    — arrangement | accrual | anticipation | action
 *   eventType   — e.g., 'document.intake', 'user.login'
 *   actorId     — filter by actor
 *   targetType  — filter by target entity type
 *   targetId    — filter by target entity ID
 *   from        — ISO datetime (inclusive)
 *   to          — ISO datetime (inclusive)
 *   limit       — max results (default 50, max 200)
 *   offset      — pagination offset
 */
router.get(
  '/events',
  requireRole('auditor', 'org_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const limit = Math.min(parseInt(req.query.limit as string) || 50, 200);
      const offset = parseInt(req.query.offset as string) || 0;

      const events = await queryAuditEvents({
        organizationId: req.user.organizationId,
        category: req.query.category as any,
        eventType: req.query.eventType as string,
        actorId: req.query.actorId as string,
        targetType: req.query.targetType as string,
        targetId: req.query.targetId as string,
        from: req.query.from ? new Date(req.query.from as string) : undefined,
        to: req.query.to ? new Date(req.query.to as string) : undefined,
        limit,
        offset,
      });

      res.json({ events, limit, offset });
    } catch (err: any) {
      console.error('[Audit] Query error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * GET /api/audit/events/:id/verify
 * Verify a specific audit event against its blockchain anchor.
 * (Tessera v3.1 §11.3 Blockchain Verification Protocol)
 *
 * Phase 1: Returns the event hash and FORAY/Kaspa TX references.
 * Full verification (steps 1-4 of §11.3) requires FORAY integration.
 */
router.get(
  '/events/:id/verify',
  requireRole('auditor') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { pool: dbPool } = require('../../db/pool');
      const result = await dbPool.query(
        `SELECT id, event_time, event_type, event_hash,
                foray_tx_id, kaspa_tx_id, is_anchored, anchored_at
         FROM audit_trail
         WHERE id = $1 AND organization_id = $2`,
        [req.params.id, req.user.organizationId]
      );

      if (result.rows.length === 0) {
        res.status(404).json({ error: 'Audit event not found' });
        return;
      }

      const event = result.rows[0];

      res.json({
        event,
        verification: {
          hashPresent: !!event.event_hash,
          forayAnchored: event.is_anchored,
          forayTxId: event.foray_tx_id,
          kaspaTxId: event.kaspa_tx_id,
          // TODO: Full verification against FORAY API and Kaspa chain
          chainVerified: null,
          message: event.is_anchored
            ? 'Event is anchored to blockchain. Full chain verification available when FORAY integration is complete.'
            : 'Event is not yet anchored. It will be committed to blockchain in the next batch.',
        },
      });
    } catch (err: any) {
      console.error('[Audit] Verify error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

export default router;
