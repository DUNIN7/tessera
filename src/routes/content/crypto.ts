// =============================================================================
// TESSERA — Deconstruction & Reconstruction Routes
//
// Content-layer routes for the crypto core pipeline.
// Mounted at /api/content/crypto/* from the content router.
//
// Routes:
//   POST  /deconstruct/:documentId       — Execute deconstruction (§8.3)
//   POST  /reconstruct/:documentId       — Reconstruct for viewer (§9)
//   GET   /reconstruct/:documentId/events — List reconstruction events
//   GET   /integrity/:documentId          — Integrity verification summary
//   POST  /keys/:documentId/rotate        — Key rotation (§10.2)
// =============================================================================

import { Router, Response } from 'express';
import { requireRole } from '../../middleware/role-guard';
import { AuthenticatedRequest } from '../../types/auth';
import { executeDeconstruction } from '../../services/crypto/deconstruction';
import { reconstructDocument } from '../../services/crypto/reconstruction';
import { getHsmProvider, getActiveKeyRecord } from '../../services/crypto/hsm';
import { reEncryptContentSet, sha512 } from '../../services/crypto/encryption';
import { recordAuditEvent } from '../../services/audit';
import { submitForayTransaction } from '../../foray';
import { pool } from '../../db/pool';
import { v4 as uuidv4 } from 'uuid';

const router = Router();

// ── Deconstruction ─────────────────────────────────────────────────────

/**
 * POST /crypto/deconstruct/:documentId
 * Execute deconstruction on an approved document. (§8.3)
 *
 * Requires org_admin — deconstruction is a privileged operation that
 * produces encrypted content sets and distributes key shares.
 *
 * Precondition: document status = 'approved', markup session approved.
 */
router.post(
  '/deconstruct/:documentId',
  requireRole('org_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { documentId } = req.params;
    const { sessionId } = req.body;

    if (!sessionId) {
      res.status(400).json({ error: 'sessionId required (the approved markup session)' });
      return;
    }

    try {
      const result = await executeDeconstruction({
        documentId,
        sessionId,
        organizationId: req.user.organizationId,
        actorId: req.user.id,
      });

      res.status(201).json({
        documentId: result.documentId,
        status: 'active',
        contentSets: result.contentSets.map(cs => ({
          identifier: cs.contentSetIdentifier,
          ciphertextHash: cs.ciphertextHash,
          algorithm: cs.algorithm,
          encryptedAt: cs.encryptedAt,
        })),
        markers: {
          count: result.markers.length,
          mergedCount: result.markers.filter(m => m.isMerged).length,
        },
        keyRecords: result.keyRecords.map(kr => ({
          id: kr.id,
          contentSet: kr.contentSetIdentifier,
          algorithm: kr.algorithm,
          shamirConfig: kr.shamirConfig,
        })),
        storageConfirmations: result.storageConfirmations,
        baseDocumentHash: result.baseDocument.hash,
        forayTxId: result.forayTxId,
        timestamp: result.timestamp,
      });
    } catch (err: any) {
      const status = err.message.includes('not found') ? 404
        : err.message.includes('not in approved') ? 409
        : err.message.includes('No content set') ? 400 : 500;
      res.status(status).json({ error: err.message });
    }
  }
);

// ── Reconstruction ─────────────────────────────────────────────────────

/**
 * POST /crypto/reconstruct/:documentId
 * Reconstruct a document for the requesting viewer. (§9)
 *
 * The viewer must specify their access level. The system verifies
 * authorization, decrypts authorized content sets, verifies integrity,
 * and returns the tailored view with redaction markers.
 */
router.post(
  '/reconstruct/:documentId',
  requireRole('viewer', 'org_admin', 'auditor', 'redactor', 'reviewer') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { documentId } = req.params;
    const { accessLevelId } = req.body;

    if (!accessLevelId) {
      res.status(400).json({ error: 'accessLevelId required' });
      return;
    }

    try {
      const view = await reconstructDocument({
        documentId,
        viewerId: req.user.id,
        accessLevelId,
        organizationId: req.user.organizationId,
      });

      res.json({
        documentId: view.documentId,
        accessLevelId: view.accessLevelId,
        reconstructionEventId: view.reconstructionEventId,
        markerWidth: view.markerWidth,
        content: JSON.parse(view.content),
        contentSetsUsed: view.contentSetsUsed,
        contentSetsRedacted: view.contentSetsRedacted,
        integrityVerification: view.integrityVerification,
        timestamp: view.timestamp,
      });
    } catch (err: any) {
      const status = err.message.includes('Authorization denied') ? 403
        : err.message.includes('not found') ? 404
        : err.message.includes('integrity') ? 500 : 500;
      res.status(status).json({ error: err.message });
    }
  }
);

/**
 * GET /crypto/reconstruct/:documentId/events
 * List reconstruction events for a document. (§11.2 Viewing level)
 * Auditor + org_admin only.
 */
router.get(
  '/reconstruct/:documentId/events',
  requireRole('auditor', 'org_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const result = await pool.query(
        `SELECT re.id, re.viewer_id, u.display_name as viewer_name,
                re.access_level_id, re.content_sets_used, re.content_sets_redacted,
                re.marker_width, re.integrity_all_passed, re.created_at
         FROM reconstruction_events re
         JOIN users u ON u.id = re.viewer_id
         WHERE re.document_id = $1 AND re.organization_id = $2
         ORDER BY re.created_at DESC
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

// ── Integrity Verification ─────────────────────────────────────────────

/**
 * GET /crypto/integrity/:documentId
 * Integrity verification summary. (§9.2, §11.3)
 * Independent verification of content set hashes against stored records.
 * Auditor + org_admin.
 */
router.get(
  '/integrity/:documentId',
  requireRole('auditor', 'org_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      // Base document
      const baseResult = await pool.query(
        `SELECT content, content_hash FROM base_documents
         WHERE document_id = $1 AND organization_id = $2`,
        [req.params.documentId, req.user.organizationId]
      );

      let baseVerified = false;
      if (baseResult.rows.length > 0) {
        const computed = sha512(baseResult.rows[0].content);
        baseVerified = computed === baseResult.rows[0].content_hash;
      }

      // Content sets — verify ciphertext hashes
      const setsResult = await pool.query(
        `SELECT content_set_identifier, encrypted_envelope, ciphertext_hash
         FROM encrypted_content_sets
         WHERE document_id = $1 AND organization_id = $2`,
        [req.params.documentId, req.user.organizationId]
      );

      const contentSetVerifications: Record<string, {
        ciphertextHashStored: string;
        ciphertextHashComputed: string;
        verified: boolean;
      }> = {};

      for (const row of setsResult.rows) {
        const envelope = JSON.parse(row.encrypted_envelope);
        const computed = sha512(Buffer.from(envelope.ciphertext, 'base64'));
        contentSetVerifications[row.content_set_identifier] = {
          ciphertextHashStored: row.ciphertext_hash,
          ciphertextHashComputed: computed,
          verified: computed === row.ciphertext_hash,
        };
      }

      const allPassed = baseVerified &&
        Object.values(contentSetVerifications).every(v => v.verified);

      res.json({
        documentId: req.params.documentId,
        baseDocumentVerified: baseVerified,
        contentSetVerifications,
        allPassed,
        verifiedAt: new Date().toISOString(),
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  }
);

// ── Key Rotation ───────────────────────────────────────────────────────

/**
 * POST /crypto/keys/:documentId/rotate
 * Rotate encryption keys for a document's content sets. (§10.2)
 * "Key rotation: re-encrypts without re-deconstruction; recorded on blockchain"
 *
 * Org admin only. Generates new keys, re-encrypts each content set,
 * deactivates old keys.
 */
router.post(
  '/keys/:documentId/rotate',
  requireRole('org_admin') as any,
  async (req: AuthenticatedRequest, res: Response) => {
    const { documentId } = req.params;
    const hsm = getHsmProvider();
    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      // Get all active encrypted content sets
      const setsResult = await client.query(
        `SELECT ecs.id, ecs.content_set_identifier, ecs.encrypted_envelope,
                ecs.key_id, ek.hsm_key_handle, ek.shamir_threshold,
                ek.shamir_total_shares
         FROM encrypted_content_sets ecs
         JOIN encryption_keys ek ON ek.id = ecs.key_id
         WHERE ecs.document_id = $1 AND ecs.organization_id = $2 AND ek.is_active = true`,
        [documentId, req.user.organizationId]
      );

      if (setsResult.rows.length === 0) {
        await client.query('COMMIT');
        res.status(404).json({ error: 'No active encrypted content sets found' });
        return;
      }

      const rotatedKeys: Array<{ contentSet: string; oldKeyId: string; newKeyId: string }> = [];

      for (const row of setsResult.rows) {
        const envelope = JSON.parse(row.encrypted_envelope);

        // Get old key
        const oldKey = await hsm.getKeyMaterial(row.hsm_key_handle);

        // Generate new key
        const { keyHandle: newHandle, keyId: newKeyId } = await hsm.generateKey();
        const newKey = await hsm.getKeyMaterial(newHandle);

        // Re-encrypt (§10.2: "re-encrypts without re-deconstruction")
        const newEnvelope = reEncryptContentSet(envelope, oldKey, newKey, newKeyId);

        // Deactivate old key
        await client.query(
          `UPDATE encryption_keys SET is_active = false, rotated_at = now() WHERE id = $1`,
          [row.key_id]
        );

        // Create new key record
        await client.query(
          `INSERT INTO encryption_keys
             (id, document_id, content_set_identifier, organization_id,
              hsm_key_handle, algorithm, shamir_threshold, shamir_total_shares,
              is_active, rotated_from_key_id)
           VALUES ($1, $2, $3, $4, $5, 'aes-256-gcm', $6, $7, true, $8)`,
          [
            newKeyId, documentId, row.content_set_identifier,
            req.user.organizationId, newHandle,
            row.shamir_threshold, row.shamir_total_shares,
            row.key_id,
          ]
        );

        // Update encrypted content set with new envelope and key
        await client.query(
          `UPDATE encrypted_content_sets
           SET encrypted_envelope = $1, ciphertext_hash = $2, key_id = $3
           WHERE id = $4`,
          [JSON.stringify(newEnvelope), newEnvelope.ciphertextHash, newKeyId, row.id]
        );

        rotatedKeys.push({
          contentSet: row.content_set_identifier,
          oldKeyId: row.key_id,
          newKeyId,
        });

        // Zero out key material
        oldKey.fill(0);
        newKey.fill(0);
      }

      await client.query('COMMIT');

      // Audit and FORAY
      await recordAuditEvent({
        category: 'action',
        eventType: 'keys.rotated',
        description: `Key rotation completed for document ${documentId}: ${rotatedKeys.length} key(s)`,
        organizationId: req.user.organizationId,
        actorId: req.user.id,
        actorRole: 'org_admin',
        actorLayer: 'content',
        targetType: 'document',
        targetId: documentId,
        metadata: { rotatedKeys },
      });

      await submitForayTransaction({
        transactionId: `TESSERA_KEY_ROTATION_${documentId}_${Date.now()}`,
        transactionType: 'key_rotation',
        action: {
          documentId,
          rotatedKeys,
          timestamp: new Date().toISOString(),
        },
      });

      res.json({
        documentId,
        rotatedKeys,
        rotatedAt: new Date().toISOString(),
      });
    } catch (err: any) {
      await client.query('ROLLBACK');
      res.status(500).json({ error: err.message });
    } finally {
      client.release();
    }
  }
);

export default router;
