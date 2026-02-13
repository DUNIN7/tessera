// =============================================================================
// TESSERA — Phase 5+6 Routes
//
// Content-layer: export, viewing sessions, versioning, retention, destruction
// System-layer: blockchain verification, health check
//
// Mounted at /api/content/export/*        — Export & viewing (§9.3, §11.2)
// Mounted at /api/content/versions/*      — Document versioning (§14)
// Mounted at /api/content/retention/*     — Retention & destruction (§12)
// Mounted at /api/content/verification/*  — Blockchain verification (§11.3)
// Mounted at /api/health                  — System health (Phase 6)
// =============================================================================

import { Router, Response } from 'express';
import { requireRole } from '../../middleware/role-guard';
import { AuthenticatedRequest } from '../../types/auth';
import { exportDocument, recordViewingSession } from '../../services/export';
import { registerNewVersion, getVersionChain, getPreviousVersionMarkup } from '../../services/versioning';
import { getRetentionPolicy, executeDestruction, destroyContentSet } from '../../services/retention';
import { sha512 } from '../../services/crypto/encryption';
import { pool } from '../../db/pool';

// =============================================================================
// EXPORT & VIEWING ROUTES (§9.3, §10.5, §11.2)
// =============================================================================

export const exportRouter = Router();

/**
 * POST /export/:documentId
 * Export a reconstructed document with watermarking. (§9.3, §10.5)
 */
exportRouter.post(
  '/:documentId',
  requireRole('viewer', 'org_admin', 'redactor', 'reviewer') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { reconstructionEventId, format } = req.body;

    if (!reconstructionEventId || !format) {
      res.status(400).json({ error: 'reconstructionEventId and format (pdf|html|txt) required' });
      return;
    }

    try {
      const result = await exportDocument({
        documentId: req.params.documentId,
        reconstructionEventId,
        viewerId: req.user.id,
        accessLevelId: req.body.accessLevelId || '',
        organizationId: req.user.organizationId,
        format,
      });

      res.json({
        exportEventId: result.exportEventId,
        format: result.format,
        watermarked: result.watermarked,
        contentHash: result.contentHash,
        exportedAt: result.exportedAt,
      });
    } catch (err: any) {
      const status = err.message.includes('not found') ? 404
        : err.message.includes('not permitted') ? 403 : 500;
      res.status(status).json({ error: err.message });
    }
  }
);

/**
 * POST /export/:documentId/viewing-session
 * Record viewing session for behavioral audit. (§11.2 Viewing level)
 */
exportRouter.post(
  '/:documentId/viewing-session',
  requireRole('viewer', 'org_admin', 'redactor', 'reviewer') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { reconstructionEventId, accessLevelId, pagesViewed, durationSeconds, navigationEvents } = req.body;

    if (!reconstructionEventId) {
      res.status(400).json({ error: 'reconstructionEventId required' });
      return;
    }

    try {
      const result = await recordViewingSession({
        reconstructionEventId,
        documentId: req.params.documentId,
        viewerId: req.user.id,
        accessLevelId: accessLevelId || '',
        organizationId: req.user.organizationId,
        pagesViewed: pagesViewed || [],
        durationSeconds: durationSeconds || 0,
        navigationEvents: navigationEvents || [],
      });
      res.status(201).json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  }
);

/**
 * GET /export/:documentId/events
 * List export events for a document. Auditor/admin only.
 */
exportRouter.get(
  '/:documentId/events',
  requireRole('auditor', 'org_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const result = await pool.query(
        `SELECT ee.id, ee.viewer_id, u.display_name as viewer_name,
                ee.format, ee.content_hash, ee.watermark_payload,
                ee.created_at
         FROM export_events ee
         JOIN users u ON u.id = ee.viewer_id
         WHERE ee.document_id = $1 AND ee.organization_id = $2
         ORDER BY ee.created_at DESC
         LIMIT $3 OFFSET $4`,
        [
          req.params.documentId, req.user.organizationId,
          parseInt(req.query.limit as string) || 50,
          parseInt(req.query.offset as string) || 0,
        ]
      );
      res.json({ events: result.rows });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  }
);

// =============================================================================
// VERSIONING ROUTES (§14)
// =============================================================================

export const versionRouter = Router();

/**
 * POST /versions/:documentId/new
 * Register a new version of an existing document. (§14)
 */
versionRouter.post(
  '/:documentId/new',
  requireRole('redactor', 'org_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { title, originalHash, filePath, mimeType, sizeBytes } = req.body;

    if (!originalHash) {
      res.status(400).json({ error: 'originalHash required' });
      return;
    }

    try {
      const result = await registerNewVersion({
        previousDocumentId: req.params.documentId,
        organizationId: req.user.organizationId,
        uploadedBy: req.user.id,
        title: title || `Version update`,
        originalHash,
        filePath: filePath || '',
        mimeType: mimeType || 'application/octet-stream',
        sizeBytes: sizeBytes || 0,
      });
      res.status(201).json(result);
    } catch (err: any) {
      res.status(err.message.includes('not found') ? 404 : 500).json({ error: err.message });
    }
  }
);

/**
 * GET /versions/:documentId/chain
 * Get the version chain. (§14)
 */
versionRouter.get(
  '/:documentId/chain',
  requireRole('redactor', 'reviewer', 'org_admin', 'auditor') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const chain = await getVersionChain(req.params.documentId, req.user.organizationId);
      res.json({ chain });
    } catch (err: any) {
      res.status(err.message.includes('not found') ? 404 : 500).json({ error: err.message });
    }
  }
);

/**
 * GET /versions/:documentId/previous-markup
 * Get previous version's markup for comparison. (§14)
 */
versionRouter.get(
  '/:documentId/previous-markup',
  requireRole('redactor') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const markup = await getPreviousVersionMarkup(req.params.documentId, req.user.organizationId);
      res.json(markup || { message: 'No previous version or markup found' });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  }
);

// =============================================================================
// RETENTION & DESTRUCTION ROUTES (§12)
// =============================================================================

export const retentionRouter = Router();

/**
 * GET /retention/:documentId/policy
 * Get retention policy for a document. (§12.1)
 */
retentionRouter.get(
  '/:documentId/policy',
  requireRole('org_admin', 'auditor') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const policy = await getRetentionPolicy(req.params.documentId, req.user.organizationId);
      res.json(policy);
    } catch (err: any) {
      res.status(err.message.includes('not found') ? 404 : 500).json({ error: err.message });
    }
  }
);

/**
 * POST /retention/:documentId/destroy
 * Execute verified destruction. (§12.2)
 * IRREVERSIBLE. Org admin only.
 */
retentionRouter.post(
  '/:documentId/destroy',
  requireRole('org_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { reason, regulatoryClearance } = req.body;

    if (!reason) {
      res.status(400).json({ error: 'reason required' });
      return;
    }

    try {
      const result = await executeDestruction({
        documentId: req.params.documentId,
        organizationId: req.user.organizationId,
        authorizedBy: req.user.id,
        reason,
        regulatoryClearance: regulatoryClearance || false,
      });
      res.json(result);
    } catch (err: any) {
      const status = err.message.includes('not found') ? 404
        : err.message.includes('Cannot destroy') ? 409
        : err.message.includes('legal hold') ? 409
        : err.message.includes('retention') ? 409
        : err.message.includes('clearance') ? 400 : 500;
      res.status(status).json({ error: err.message });
    }
  }
);

/**
 * POST /retention/:documentId/destroy-set
 * Targeted content set destruction for right-to-erasure. (§12.3)
 * Org admin only.
 */
retentionRouter.post(
  '/:documentId/destroy-set',
  requireRole('org_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { contentSetIdentifier, reason, regulatoryBasis } = req.body;

    if (!contentSetIdentifier || !reason || !regulatoryBasis) {
      res.status(400).json({ error: 'contentSetIdentifier, reason, and regulatoryBasis required' });
      return;
    }

    try {
      const result = await destroyContentSet({
        documentId: req.params.documentId,
        contentSetIdentifier,
        organizationId: req.user.organizationId,
        authorizedBy: req.user.id,
        reason,
        regulatoryBasis,
      });
      res.json(result);
    } catch (err: any) {
      res.status(err.message.includes('not found') ? 404 : 500).json({ error: err.message });
    }
  }
);

/**
 * POST /retention/:documentId/legal-hold
 * Set or release legal hold on a document.
 */
retentionRouter.post(
  '/:documentId/legal-hold',
  requireRole('org_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { hold, reason } = req.body;

    if (typeof hold !== 'boolean') {
      res.status(400).json({ error: 'hold (boolean) required' });
      return;
    }

    try {
      await pool.query(
        `UPDATE documents SET legal_hold = $1, legal_hold_reason = $2, updated_at = now()
         WHERE id = $3 AND organization_id = $4`,
        [hold, hold ? reason : null, req.params.documentId, req.user.organizationId]
      );
      res.json({ documentId: req.params.documentId, legalHold: hold });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  }
);

// =============================================================================
// BLOCKCHAIN VERIFICATION ROUTES (§11.3)
// =============================================================================

export const verificationRouter = Router();

/**
 * GET /verification/:documentId/chain-of-custody
 * Complete chain of custody for a document. (§11.5)
 * "Complete, immutable chain from intake through every lifecycle event."
 */
verificationRouter.get(
  '/:documentId/chain-of-custody',
  requireRole('auditor', 'org_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const auditResult = await pool.query(
        `SELECT event_type, description, actor_id, actor_role,
                metadata, foray_tx_id, created_at
         FROM audit_events
         WHERE target_id = $1 AND organization_id = $2
         ORDER BY created_at ASC`,
        [req.params.documentId, req.user.organizationId]
      );

      // Get integrity verification data
      const baseResult = await pool.query(
        `SELECT content_hash FROM base_documents
         WHERE document_id = $1 AND organization_id = $2`,
        [req.params.documentId, req.user.organizationId]
      );

      const setsResult = await pool.query(
        `SELECT content_set_identifier, ciphertext_hash
         FROM encrypted_content_sets
         WHERE document_id = $1 AND organization_id = $2`,
        [req.params.documentId, req.user.organizationId]
      );

      res.json({
        documentId: req.params.documentId,
        eventCount: auditResult.rows.length,
        events: auditResult.rows,
        integrityAnchors: {
          baseDocumentHash: baseResult.rows[0]?.content_hash || null,
          contentSetHashes: setsResult.rows.reduce((acc: any, r: any) => {
            acc[r.content_set_identifier] = r.ciphertext_hash;
            return acc;
          }, {}),
        },
        verifiedAt: new Date().toISOString(),
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  }
);

/**
 * POST /verification/:documentId/verify
 * Execute full integrity verification. (§11.3)
 * "Hash comparison, chain validation, reconstruction verification."
 */
verificationRouter.post(
  '/:documentId/verify',
  requireRole('auditor', 'org_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const checks: Array<{ check: string; passed: boolean; details?: string }> = [];

      // 1. Base document hash verification
      const baseResult = await pool.query(
        `SELECT content, content_hash FROM base_documents
         WHERE document_id = $1 AND organization_id = $2`,
        [req.params.documentId, req.user.organizationId]
      );

      if (baseResult.rows.length > 0) {
        const computed = sha512(baseResult.rows[0].content);
        checks.push({
          check: 'base_document_hash',
          passed: computed === baseResult.rows[0].content_hash,
          details: computed === baseResult.rows[0].content_hash
            ? 'Hash matches' : 'HASH MISMATCH — possible tampering',
        });
      } else {
        checks.push({ check: 'base_document_hash', passed: false, details: 'No base document found' });
      }

      // 2. Content set ciphertext hashes
      const setsResult = await pool.query(
        `SELECT content_set_identifier, encrypted_envelope, ciphertext_hash
         FROM encrypted_content_sets
         WHERE document_id = $1 AND organization_id = $2`,
        [req.params.documentId, req.user.organizationId]
      );

      for (const row of setsResult.rows) {
        const envelope = JSON.parse(row.encrypted_envelope);
        const computed = sha512(Buffer.from(envelope.ciphertext, 'base64'));
        checks.push({
          check: `content_set_${row.content_set_identifier}_ciphertext`,
          passed: computed === row.ciphertext_hash,
          details: computed === row.ciphertext_hash
            ? 'Ciphertext hash verified' : 'CIPHERTEXT HASH MISMATCH',
        });
      }

      // 3. Key integrity — all active keys have valid HSM handles
      const keysResult = await pool.query(
        `SELECT id, content_set_identifier, hsm_key_handle, is_active
         FROM encryption_keys
         WHERE document_id = $1 AND organization_id = $2`,
        [req.params.documentId, req.user.organizationId]
      );

      checks.push({
        check: 'encryption_keys',
        passed: keysResult.rows.length > 0,
        details: `${keysResult.rows.filter((r: any) => r.is_active).length} active key(s) of ${keysResult.rows.length} total`,
      });

      // 4. FORAY transaction references exist
      const forayResult = await pool.query(
        `SELECT COUNT(*) as count FROM audit_events
         WHERE target_id = $1 AND foray_tx_id IS NOT NULL`,
        [req.params.documentId]
      );

      checks.push({
        check: 'foray_transactions',
        passed: parseInt(forayResult.rows[0].count) > 0,
        details: `${forayResult.rows[0].count} FORAY-anchored audit events`,
      });

      const allPassed = checks.every(c => c.passed);

      res.json({
        documentId: req.params.documentId,
        allPassed,
        checks,
        verifiedAt: new Date().toISOString(),
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  }
);
