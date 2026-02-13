// =============================================================================
// TESSERA — Access Control Layer Routes
//
// All routes under /api/access-control/ are guarded by
// requireLayer('access_control'). Only access-control-layer roles
// (acl_author, asset_provisioner) can access these endpoints.
// (Parallel Architecture Evaluation §9)
//
// In Tier 1, these routes manage the conventional RBAC grants.
// In Tier 2/3 (future), they will interface with Ova egg deployment
// and management on the Kaspa blockDAG.
//
// Phase 1 routes:
//   POST   /api/access-control/grants          — Grant user access
//   DELETE /api/access-control/grants/:id       — Revoke access
//   GET    /api/access-control/grants           — List grants
// =============================================================================

import { Router, Response } from 'express';
import { pool } from '../../db/pool';
import { authenticate } from '../../middleware/authenticate';
import { requireLayer } from '../../middleware/layer-guard';
import { requireRole } from '../../middleware/role-guard';
import { enforceTenantIsolation } from '../../middleware/tenant-isolation';
import { AuthenticatedRequest } from '../../types/auth';
import { recordAuditEvent } from '../../services/audit';

const router = Router();

// All access-control routes require authentication + access_control layer
router.use(authenticate as any);
router.use(requireLayer('access_control') as any);
router.use(enforceTenantIsolation as any);

/**
 * POST /api/access-control/grants
 * Grant a user access to a document at a specific access level.
 * ACL author only. (Parallel Eval §9: creates authorization rules)
 *
 * In Tier 1: inserts into user_access_grants.
 * In Tier 2/3 (future): deploys/updates ACL + Group Eggs.
 */
router.post(
  '/grants',
  requireRole('acl_author') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { userId, documentId, accessLevelId, expiresAt } = req.body;

    if (!userId || !documentId || !accessLevelId) {
      res.status(400).json({ error: 'userId, documentId, and accessLevelId required' });
      return;
    }

    try {
      // Verify the target user, document, and access level belong to same org
      const validationResult = await pool.query(
        `SELECT 
           (SELECT organization_id FROM users WHERE id = $1) as user_org,
           (SELECT organization_id FROM documents WHERE id = $2) as doc_org,
           (SELECT organization_id FROM access_levels WHERE id = $3) as level_org`,
        [userId, documentId, accessLevelId]
      );

      const v = validationResult.rows[0];
      if (!v.user_org || !v.doc_org || !v.level_org) {
        res.status(404).json({ error: 'User, document, or access level not found' });
        return;
      }

      if (v.user_org !== v.doc_org || v.doc_org !== v.level_org) {
        res.status(403).json({ error: 'Cross-organization grant not permitted without trust group' });
        return;
      }

      const result = await pool.query(
        `INSERT INTO user_access_grants (user_id, document_id, access_level_id, granted_by, expires_at)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, user_id, document_id, access_level_id, expires_at, created_at`,
        [userId, documentId, accessLevelId, req.user.id, expiresAt || null]
      );

      const grant = result.rows[0];

      await recordAuditEvent({
        category: 'action',
        eventType: 'access_grant.create',
        description: `Access granted: user ${userId} → document ${documentId} at level ${accessLevelId}`,
        organizationId: req.user.organizationId,
        actorId: req.user.id,
        actorRole: 'acl_author',
        actorLayer: 'access_control',
        targetType: 'access_grant',
        targetId: grant.id,
        metadata: { userId, documentId, accessLevelId, expiresAt },
      });

      res.status(201).json({ grant });
    } catch (err: any) {
      if (err.code === '23505') {
        res.status(409).json({ error: 'Grant already exists for this user/document/level combination' });
        return;
      }
      console.error('[AccessControl] Grant create error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * DELETE /api/access-control/grants/:id
 * Revoke an access grant. ACL author only.
 *
 * Tessera v3.1 §5.4: revoked access behaves as no-access.
 * In Tier 2/3 (future): updates Group Egg roster, invalidating proofs.
 */
router.delete(
  '/grants/:id',
  requireRole('acl_author') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const result = await pool.query(
        `UPDATE user_access_grants
         SET is_revoked = true, revoked_at = now(), revoked_by = $1
         WHERE id = $2
           AND is_revoked = false
         RETURNING id, user_id, document_id, access_level_id`,
        [req.user.id, req.params.id]
      );

      if (result.rows.length === 0) {
        res.status(404).json({ error: 'Grant not found or already revoked' });
        return;
      }

      const grant = result.rows[0];

      await recordAuditEvent({
        category: 'action',
        eventType: 'access_grant.revoke',
        description: `Access revoked: grant ${grant.id}`,
        organizationId: req.user.organizationId,
        actorId: req.user.id,
        actorRole: 'acl_author',
        actorLayer: 'access_control',
        targetType: 'access_grant',
        targetId: grant.id,
        metadata: { userId: grant.user_id, documentId: grant.document_id },
      });

      res.json({ message: 'Grant revoked', grant });
    } catch (err: any) {
      console.error('[AccessControl] Grant revoke error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * GET /api/access-control/grants
 * List access grants. ACL author sees all grants for the org.
 * Asset provisioner sees grants relevant to provisioned assets.
 */
router.get('/grants', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const result = await pool.query(
      `SELECT g.id, g.user_id, g.document_id, g.access_level_id,
              g.granted_by, g.expires_at, g.is_revoked, g.revoked_at,
              g.created_at,
              u.display_name as user_name, u.email as user_email,
              d.title as document_title,
              al.name as access_level_name
       FROM user_access_grants g
       JOIN users u ON u.id = g.user_id
       JOIN documents d ON d.id = g.document_id
       JOIN access_levels al ON al.id = g.access_level_id
       WHERE d.organization_id = $1
       ORDER BY g.created_at DESC`,
      [req.user.organizationId]
    );

    res.json({ grants: result.rows });
  } catch (err: any) {
    console.error('[AccessControl] Grant list error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
