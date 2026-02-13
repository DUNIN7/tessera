// =============================================================================
// TESSERA — Content Layer Routes
//
// All routes under /api/content/ are guarded by requireLayer('content').
// Only content-layer roles can access these endpoints.
// (Parallel Architecture Evaluation §9)
//
// Routes:
//   GET    /api/content/organizations          — List orgs (sys admin)
//   GET    /api/content/documents              — List documents (org-scoped)
//   POST   /api/content/documents              — Register document intake
//   POST   /api/content/documents/upload       — Upload + full intake pipeline
//   GET    /api/content/documents/:id          — Get document detail
//   GET    /api/content/documents/:id/scan     — Get stego scan results
//   POST   /api/content/documents/:id/disposition — Admin resolve flagged doc
//   GET    /api/content/access-levels          — List access levels (org-scoped)
//   POST   /api/content/access-levels          — Create access level
//   GET    /api/content/users                  — List users (org admin)
// =============================================================================

import { Router, Response } from 'express';
import multer from 'multer';
import * as path from 'path';
import * as fs from 'fs';
import { pool } from '../../db/pool';
import { authenticate } from '../../middleware/authenticate';
import { requireLayer } from '../../middleware/layer-guard';
import { requireRole } from '../../middleware/role-guard';
import { enforceTenantIsolation } from '../../middleware/tenant-isolation';
import { AuthenticatedRequest } from '../../types/auth';
import { recordAuditEvent } from '../../services/audit';
import { executeIntakePipeline, resolveIntakeFlag } from '../../services/pipeline';
import markupRouter from './markup';
import cryptoRouter from './crypto';
import { exportRouter, versionRouter, retentionRouter, verificationRouter } from './phase56';

const router = Router();

// ── File Upload Configuration ──────────────────────────────────────────

const UPLOAD_DIR = process.env.TESSERA_UPLOAD_DIR || '/app/data/uploads';

// Ensure upload directory exists
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename: (_req, file, cb) => {
      // Unique filename to prevent collisions; preserve extension for MIME checks
      const uniqueName = `${Date.now()}-${Math.random().toString(36).slice(2)}${path.extname(file.originalname)}`;
      cb(null, uniqueName);
    },
  }),
  limits: {
    fileSize: 500 * 1024 * 1024, // 500MB max
    files: 1,                    // Single file per request
  },
});

// All content routes require authentication + content layer
router.use(authenticate as any);
router.use(requireLayer('content') as any);
router.use(enforceTenantIsolation as any);

// ── Markup Engine Sub-Router (§7, §8) ──────────────────────────────────
router.use('/markup', markupRouter);

// ── Crypto Core Sub-Router (§8.3, §9, §10) ────────────────────────────
router.use('/crypto', cryptoRouter);

// ── Export & Viewing Sub-Router (§9.3, §10.5, §11.2) ──────────────────
router.use('/export', exportRouter);

// ── Versioning Sub-Router (§14) ────────────────────────────────────────
router.use('/versions', versionRouter);

// ── Retention & Destruction Sub-Router (§12) ───────────────────────────
router.use('/retention', retentionRouter);

// ── Blockchain Verification Sub-Router (§11.3) ────────────────────────
router.use('/verification', verificationRouter);

// ── Organizations ──────────────────────────────────────────────────────

/**
 * GET /api/content/organizations
 * List organizations. System admin: all orgs. Org admin: own org only.
 */
router.get(
  '/organizations',
  requireRole('system_admin', 'org_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const isSystemAdmin = req.user.roles.includes('system_admin');
      const result = isSystemAdmin
        ? await pool.query(`SELECT id, name, slug, is_active, created_at FROM organizations ORDER BY name`)
        : await pool.query(
            `SELECT id, name, slug, is_active, created_at FROM organizations WHERE id = $1`,
            [req.user.organizationId]
          );

      res.json({ organizations: result.rows });
    } catch (err: any) {
      console.error('[Content] Org list error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// ── Documents ──────────────────────────────────────────────────────────

/**
 * GET /api/content/documents
 * List documents for the user's organization.
 * Filtered by role: viewers see only documents they have grants for;
 * redactors/reviewers see documents assigned to them; admins see all.
 */
router.get('/documents', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const roles = req.user.roles;
    let result;

    if (roles.includes('org_admin') || roles.includes('system_admin')) {
      result = await pool.query(
        `SELECT id, title, original_filename, mime_type, status, version_number, created_at, updated_at
         FROM documents WHERE organization_id = $1 ORDER BY updated_at DESC`,
        [req.user.organizationId]
      );
    } else if (roles.includes('viewer')) {
      // Viewers see only documents they have active grants for
      result = await pool.query(
        `SELECT DISTINCT d.id, d.title, d.original_filename, d.mime_type, d.status, d.version_number, d.created_at, d.updated_at
         FROM documents d
         JOIN user_access_grants g ON g.document_id = d.id
         WHERE d.organization_id = $1
           AND g.user_id = $2
           AND g.is_revoked = false
           AND d.status = 'active'
         ORDER BY d.updated_at DESC`,
        [req.user.organizationId, req.user.id]
      );
    } else {
      // Redactors, reviewers, auditors — see org documents
      result = await pool.query(
        `SELECT id, title, original_filename, mime_type, status, version_number, created_at, updated_at
         FROM documents WHERE organization_id = $1 ORDER BY updated_at DESC`,
        [req.user.organizationId]
      );
    }

    res.json({ documents: result.rows });
  } catch (err: any) {
    console.error('[Content] Document list error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/content/documents
 * Register a new document at intake. (Tessera v3.1 §6)
 * Only org admin and redactor can initiate intake.
 *
 * Phase 1: Metadata registration only (preserved for lightweight use).
 * Phase 2: Use POST /documents/upload for full pipeline with file.
 */
router.post(
  '/documents',
  requireRole('org_admin', 'redactor') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { title, originalFilename, mimeType, originalSizeBytes, originalHash } = req.body;

    if (!title || !originalFilename || !mimeType || !originalSizeBytes || !originalHash) {
      res.status(400).json({ error: 'Missing required fields: title, originalFilename, mimeType, originalSizeBytes, originalHash' });
      return;
    }

    try {
      const result = await pool.query(
        `INSERT INTO documents (organization_id, title, original_filename, mime_type, original_size_bytes, original_hash, status)
         VALUES ($1, $2, $3, $4, $5, $6, 'intake')
         RETURNING id, title, status, created_at`,
        [req.user.organizationId, title, originalFilename, mimeType, originalSizeBytes, originalHash]
      );

      const doc = result.rows[0];

      await recordAuditEvent({
        category: 'arrangement',
        eventType: 'document.intake',
        description: `Document "${title}" registered at intake`,
        organizationId: req.user.organizationId,
        actorId: req.user.id,
        actorRole: req.user.roles[0],
        actorLayer: 'content',
        targetType: 'document',
        targetId: doc.id,
        metadata: { originalFilename, mimeType, originalHash },
      });

      res.status(201).json({ document: doc });
    } catch (err: any) {
      console.error('[Content] Document create error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * POST /api/content/documents/upload
 * Full intake pipeline: upload file → validate → normalize → scan → register.
 * (Tessera v3.1 §6: complete intake flow)
 *
 * Multipart form data:
 *   file  — the document file (required)
 *   title — document title (required)
 *
 * Returns the complete pipeline result including document ID,
 * hashes, validation, normalization, and scan results.
 *
 * Status after pipeline:
 *   intake_cleared — clean, ready for markup
 *   intake_flagged — findings require admin disposition before markup
 *   rejected       — format validation failed
 */
router.post(
  '/documents/upload',
  requireRole('org_admin', 'redactor') as any,
  upload.single('file'),
  async (req: AuthenticatedRequest, res: Response) => {
    if (!req.file) {
      res.status(400).json({ error: 'File is required' });
      return;
    }

    const title = req.body.title;
    if (!title) {
      // Clean up uploaded file
      fs.unlinkSync(req.file.path);
      res.status(400).json({ error: 'Title is required' });
      return;
    }

    try {
      const result = await executeIntakePipeline({
        filePath: req.file.path,
        originalFilename: req.file.originalname,
        declaredMimeType: req.file.mimetype,
        title,
        organizationId: req.user.organizationId,
        actorId: req.user.id,
        actorRole: req.user.roles[0],
      });

      const statusCode = result.finalStatus === 'rejected' ? 422 : 201;

      res.status(statusCode).json({
        document: {
          id: result.documentId,
          title,
          status: result.finalStatus,
          originalHash: result.originalHash,
        },
        pipeline: {
          validation: {
            valid: result.validation.valid,
            category: result.validation.category,
            sizeBytes: result.validation.sizeBytes,
            unsupportedFlags: result.validation.unsupportedFlags,
            errors: result.validation.errors,
          },
          normalization: result.normalization ? {
            success: result.normalization.success,
            normalizedHash: result.normalization.normalizedHash,
            metadata: result.normalization.metadata,
          } : null,
          stegoScan: result.stegoScan ? {
            overallSeverity: result.stegoScan.overallSeverity,
            findingCount: result.stegoScan.findings.length,
            findings: result.stegoScan.findings.map(f => ({
              id: f.id,
              category: f.category,
              severity: f.severity,
              description: f.description,
              location: f.location,
              confidence: f.confidence,
            })),
            scannerVersion: result.stegoScan.scannerVersion,
          } : null,
        },
        errors: result.errors,
      });
    } catch (err: any) {
      console.error('[Content] Upload pipeline error:', err.message);
      // Clean up uploaded file on error
      if (req.file?.path) {
        try { fs.unlinkSync(req.file.path); } catch {}
      }
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * GET /api/content/documents/:id/scan
 * Get stego scan results for a document. (Tessera v3.1 §6.3)
 * Available to org_admin, redactor, reviewer, auditor.
 */
router.get(
  '/documents/:id/scan',
  requireRole('org_admin', 'redactor', 'reviewer', 'auditor') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const result = await pool.query(
        `SELECT id, title, status, stego_scan_result
         FROM documents
         WHERE id = $1 AND organization_id = $2`,
        [req.params.id, req.user.organizationId]
      );

      if (result.rows.length === 0) {
        res.status(404).json({ error: 'Document not found' });
        return;
      }

      const doc = result.rows[0];

      if (!doc.stego_scan_result) {
        res.json({
          documentId: doc.id,
          title: doc.title,
          status: doc.status,
          scanComplete: false,
          message: 'Scan has not yet been performed',
        });
        return;
      }

      res.json({
        documentId: doc.id,
        title: doc.title,
        status: doc.status,
        scan: doc.stego_scan_result,
      });
    } catch (err: any) {
      console.error('[Content] Scan results error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * POST /api/content/documents/:id/disposition
 * Admin resolves a flagged document's intake findings. (Tessera v3.1 §6.3)
 * "Admin decides: proceed (accepting risk), sanitize flagged elements, or reject."
 *
 * Body:
 *   disposition — 'proceed' | 'sanitize' | 'reject'
 *   notes       — admin explanation for the decision
 */
router.post(
  '/documents/:id/disposition',
  requireRole('org_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { disposition, notes } = req.body;

    if (!disposition || !['proceed', 'sanitize', 'reject'].includes(disposition)) {
      res.status(400).json({ error: 'disposition required: proceed | sanitize | reject' });
      return;
    }

    try {
      const result = await resolveIntakeFlag({
        documentId: req.params.id,
        disposition,
        adminId: req.user.id,
        notes: notes || '',
        organizationId: req.user.organizationId,
      });

      res.json({
        documentId: req.params.id,
        newStatus: result.newStatus,
        disposition,
      });
    } catch (err: any) {
      if (err.message.includes('not found') || err.message.includes('not "intake_flagged"')) {
        res.status(400).json({ error: err.message });
        return;
      }
      console.error('[Content] Disposition error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * GET /api/content/documents/:id
 * Get document detail. Tenant-scoped.
 */
router.get('/documents/:id', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const result = await pool.query(
      `SELECT d.*, 
              (SELECT json_agg(json_build_object(
                'id', cs.id, 'setIdentifier', cs.set_identifier, 
                'label', cs.label, 'isDestroyed', cs.is_destroyed
              )) FROM content_sets cs WHERE cs.document_id = d.id) as content_sets
       FROM documents d
       WHERE d.id = $1 AND d.organization_id = $2`,
      [req.params.id, req.user.organizationId]
    );

    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Document not found' });
      return;
    }

    res.json({ document: result.rows[0] });
  } catch (err: any) {
    console.error('[Content] Document detail error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Access Levels ──────────────────────────────────────────────────────

/**
 * GET /api/content/access-levels
 * List access levels for the org. (Tessera v3.1 §5.2)
 */
router.get('/access-levels', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const result = await pool.query(
      `SELECT al.id, al.name, al.description, al.export_permitted,
              al.expires_at, al.is_active, al.created_at,
              (SELECT json_agg(cs.set_identifier)
               FROM access_level_content_sets alcs
               JOIN content_sets cs ON cs.id = alcs.content_set_id
               WHERE alcs.access_level_id = al.id) as content_sets
       FROM access_levels al
       WHERE al.organization_id = $1
       ORDER BY al.name`,
      [req.user.organizationId]
    );

    res.json({ accessLevels: result.rows });
  } catch (err: any) {
    console.error('[Content] Access level list error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/content/access-levels
 * Create a new access level. Org admin only. (Tessera v3.1 §5.2)
 */
router.post(
  '/access-levels',
  requireRole('org_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { name, description, exportPermitted, expiresAt } = req.body;

    if (!name) {
      res.status(400).json({ error: 'Name required' });
      return;
    }

    try {
      const result = await pool.query(
        `INSERT INTO access_levels (organization_id, name, description, export_permitted, expires_at)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, name, description, export_permitted, expires_at, is_active, created_at`,
        [req.user.organizationId, name, description || null, exportPermitted || false, expiresAt || null]
      );

      const level = result.rows[0];

      await recordAuditEvent({
        category: 'arrangement',
        eventType: 'access_level.create',
        description: `Access level "${name}" created`,
        organizationId: req.user.organizationId,
        actorId: req.user.id,
        actorRole: 'org_admin',
        actorLayer: 'content',
        targetType: 'access_level',
        targetId: level.id,
        metadata: { name, exportPermitted },
      });

      res.status(201).json({ accessLevel: level });
    } catch (err: any) {
      if (err.code === '23505') {
        res.status(409).json({ error: `Access level "${name}" already exists` });
        return;
      }
      console.error('[Content] Access level create error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// ── Users ──────────────────────────────────────────────────────────────

/**
 * GET /api/content/users
 * List users for the org. Org admin only. (Tessera v3.1 §4)
 */
router.get(
  '/users',
  requireRole('org_admin', 'system_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const result = await pool.query(
        `SELECT u.id, u.email, u.display_name, u.mfa_enrolled,
                u.hardware_token_registered, u.is_active, u.created_at,
                (SELECT json_agg(json_build_object('role', ur.role, 'layer', ur.layer))
                 FROM user_roles ur WHERE ur.user_id = u.id) as roles
         FROM users u
         WHERE u.organization_id = $1
         ORDER BY u.display_name`,
        [req.user.organizationId]
      );

      res.json({ users: result.rows });
    } catch (err: any) {
      console.error('[Content] User list error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

export default router;
