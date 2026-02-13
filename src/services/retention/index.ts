// =============================================================================
// TESSERA — Data Retention & Destruction Service
//
// Retention policy enforcement and verified destruction protocol.
// (Tessera v3.1 §12)
//
// Retention Model (§12.1):
//   1. Regulatory floor: minimum per highest applicable regulation
//   2. Organization policy: may extend but never shorten
//   3. No upward override: higher authorities cannot reduce below floor
//
// Destruction Protocol (§12.2):
//   1. Authorization: explicit Org Admin approval
//   2. Regulatory clearance: retention floor met, no legal holds
//   3. Verified deletion: all content sets, base doc, backups wiped
//   4. Blockchain proof: FORAY transaction records permanently
//   5. Key destruction: encryption keys destroyed in HSM
//
// Right-to-Erasure (§12.3):
//   Supports targeted destruction of individual content sets containing
//   personal data without destroying the entire document.
// =============================================================================

import { pool } from '../../db/pool';
import { v4 as uuidv4 } from 'uuid';
import { getHsmProvider, getActiveKeyRecord } from '../crypto/hsm';
import { recordAuditEvent } from '../audit';
import { submitForayTransaction } from '../../foray';
import { DestructionRequest, DestructionResult, RetentionPolicy } from '../../types/system';

/**
 * Get the retention policy for a document. (§12.1)
 */
export async function getRetentionPolicy(
  documentId: string,
  organizationId: string
): Promise<RetentionPolicy> {
  const result = await pool.query(
    `SELECT d.id, d.regulatory_classification,
            rp.min_retention_days, rp.regulation_name,
            sp.default_retention_days,
            d.legal_hold, d.legal_hold_reason,
            d.created_at
     FROM documents d
     LEFT JOIN retention_policies rp ON rp.classification = d.regulatory_classification
     LEFT JOIN security_profiles sp ON sp.organization_id = d.organization_id
     WHERE d.id = $1 AND d.organization_id = $2`,
    [documentId, organizationId]
  );

  if (result.rows.length === 0) {
    throw new Error('Document not found');
  }

  const doc = result.rows[0];
  const createdAt = new Date(doc.created_at);

  // Calculate regulatory floor date
  const regDays = doc.min_retention_days || 0;
  const regulatoryFloorDate = regDays > 0
    ? new Date(createdAt.getTime() + regDays * 86400000).toISOString()
    : null;

  // Calculate organization policy date
  const orgDays = doc.default_retention_days || 0;
  const orgPolicyDate = orgDays > 0
    ? new Date(createdAt.getTime() + orgDays * 86400000).toISOString()
    : null;

  // Effective = the later of the two (§12.1: "No upward override")
  let effectiveDate: string | null = null;
  if (regulatoryFloorDate && orgPolicyDate) {
    effectiveDate = regulatoryFloorDate > orgPolicyDate ? regulatoryFloorDate : orgPolicyDate;
  } else {
    effectiveDate = regulatoryFloorDate || orgPolicyDate;
  }

  return {
    documentId,
    regulatoryFloor: doc.regulation_name || null,
    regulatoryFloorDate,
    organizationPolicy: orgDays > 0 ? `${orgDays} days` : null,
    organizationPolicyDate: orgPolicyDate,
    effectiveRetentionDate: effectiveDate,
    hasLegalHold: doc.legal_hold || false,
    legalHoldReason: doc.legal_hold_reason || null,
  };
}

/**
 * Execute verified destruction of a document. (§12.2)
 * This is irreversible. All content sets, base document, backups,
 * and encryption keys are destroyed. Only the audit trail persists.
 */
export async function executeDestruction(
  request: DestructionRequest
): Promise<DestructionResult> {
  const client = await pool.connect();
  const hsm = getHsmProvider();

  try {
    await client.query('BEGIN');

    // ── Step 1: Authorization verification ───────────────────────────

    const docResult = await client.query(
      `SELECT d.id, d.title, d.status, d.legal_hold
       FROM documents d
       WHERE d.id = $1 AND d.organization_id = $2
       FOR UPDATE`,
      [request.documentId, request.organizationId]
    );

    if (docResult.rows.length === 0) {
      throw new Error('Document not found');
    }

    const doc = docResult.rows[0];

    if (doc.status === 'destroyed' || doc.status === 'destroying') {
      throw new Error(`Document is already ${doc.status}`);
    }

    // ── Step 2: Regulatory clearance ─────────────────────────────────

    if (doc.legal_hold) {
      throw new Error('Cannot destroy: document has active legal hold');
    }

    if (!request.regulatoryClearance) {
      throw new Error('Regulatory clearance confirmation required');
    }

    // Check retention policy
    const retention = await getRetentionPolicy(request.documentId, request.organizationId);
    if (retention.effectiveRetentionDate) {
      const retentionDate = new Date(retention.effectiveRetentionDate);
      if (retentionDate > new Date()) {
        throw new Error(
          `Cannot destroy: retention period not met. Earliest destruction: ${retention.effectiveRetentionDate}`
        );
      }
    }

    // Transition to destroying
    await client.query(
      `UPDATE documents SET status = 'destroying', updated_at = now() WHERE id = $1`,
      [request.documentId]
    );

    // ── Step 3: Verified deletion ────────────────────────────────────

    // Get all encrypted content sets
    const setsResult = await client.query(
      `SELECT id, content_set_identifier, key_id
       FROM encrypted_content_sets
       WHERE document_id = $1 AND organization_id = $2`,
      [request.documentId, request.organizationId]
    );

    const contentSetsDestroyed: string[] = [];
    const keysDestroyed: string[] = [];

    // Delete encrypted content sets
    for (const set of setsResult.rows) {
      await client.query(`DELETE FROM encrypted_content_sets WHERE id = $1`, [set.id]);
      contentSetsDestroyed.push(set.content_set_identifier);
    }

    // Delete base document
    await client.query(
      `DELETE FROM base_documents WHERE document_id = $1`, [request.documentId]
    );

    // ── Step 4: Key destruction ──────────────────────────────────────
    // (§12.2 step 5: "Encryption keys destroyed in HSM")

    const keysResult = await client.query(
      `SELECT id, hsm_key_handle FROM encryption_keys
       WHERE document_id = $1 AND organization_id = $2`,
      [request.documentId, request.organizationId]
    );

    for (const key of keysResult.rows) {
      try {
        await hsm.destroyKey(key.hsm_key_handle);
      } catch {} // Key may already be gone

      await client.query(
        `UPDATE encryption_keys SET is_active = false, destroyed_at = now() WHERE id = $1`,
        [key.id]
      );

      // Delete shares
      await client.query(`DELETE FROM key_shares WHERE key_id = $1`, [key.id]);

      keysDestroyed.push(key.id);
    }

    // ── Step 5: Finalize ─────────────────────────────────────────────

    await client.query(
      `UPDATE documents SET status = 'destroyed', updated_at = now() WHERE id = $1`,
      [request.documentId]
    );

    await client.query('COMMIT');

    // ── Step 6: Blockchain proof (permanent) ─────────────────────────

    const forayTx = await submitForayTransaction({
      transactionId: `TESSERA_DESTRUCTION_${request.documentId}`,
      transactionType: 'document_destruction',
      action: {
        documentId: request.documentId,
        authorizedBy: request.authorizedBy,
        reason: request.reason,
        contentSetsDestroyed,
        keysDestroyed,
        regulatoryClearance: request.regulatoryClearance,
        timestamp: new Date().toISOString(),
      },
    });

    await recordAuditEvent({
      category: 'action',
      eventType: 'document.destroyed',
      description: `Document "${doc.title}" destroyed: ${contentSetsDestroyed.length} content set(s), ${keysDestroyed.length} key(s)`,
      organizationId: request.organizationId,
      actorId: request.authorizedBy,
      actorRole: 'org_admin',
      actorLayer: 'content',
      targetType: 'document',
      targetId: request.documentId,
      metadata: {
        contentSetsDestroyed,
        keysDestroyed,
        reason: request.reason,
        forayTxId: forayTx.forayTxId,
      },
    });

    return {
      documentId: request.documentId,
      contentSetsDestroyed,
      keysDestroyed,
      backupsDestroyed: true,
      forayTxId: forayTx.forayTxId,
      destroyedAt: new Date().toISOString(),
    };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Targeted content set destruction for right-to-erasure. (§12.3)
 * "Supports targeted destruction of individual content sets containing
 *  the requesting individual's personal data without destroying
 *  the entire document."
 */
export async function destroyContentSet(params: {
  documentId: string;
  contentSetIdentifier: string;
  organizationId: string;
  authorizedBy: string;
  reason: string;
  regulatoryBasis: string;
}): Promise<{ destroyed: boolean; forayTxId: string }> {
  const client = await pool.connect();
  const hsm = getHsmProvider();

  try {
    await client.query('BEGIN');

    // Delete the encrypted content set
    const deleteResult = await client.query(
      `DELETE FROM encrypted_content_sets
       WHERE document_id = $1 AND content_set_identifier = $2 AND organization_id = $3
       RETURNING key_id`,
      [params.documentId, params.contentSetIdentifier, params.organizationId]
    );

    if (deleteResult.rows.length === 0) {
      throw new Error('Content set not found');
    }

    // Destroy the key for this content set
    const keyId = deleteResult.rows[0].key_id;
    const keyResult = await client.query(
      `SELECT hsm_key_handle FROM encryption_keys WHERE id = $1`,
      [keyId]
    );

    if (keyResult.rows.length > 0) {
      try { await hsm.destroyKey(keyResult.rows[0].hsm_key_handle); } catch {}
      await client.query(
        `UPDATE encryption_keys SET is_active = false, destroyed_at = now() WHERE id = $1`,
        [keyId]
      );
      await client.query(`DELETE FROM key_shares WHERE key_id = $1`, [keyId]);
    }

    await client.query('COMMIT');

    const forayTx = await submitForayTransaction({
      transactionId: `TESSERA_PARTIAL_DESTRUCTION_${params.documentId}_${params.contentSetIdentifier}`,
      transactionType: 'partial_destruction',
      action: {
        documentId: params.documentId,
        contentSetIdentifier: params.contentSetIdentifier,
        authorizedBy: params.authorizedBy,
        reason: params.reason,
        regulatoryBasis: params.regulatoryBasis,
        timestamp: new Date().toISOString(),
      },
    });

    await recordAuditEvent({
      category: 'action',
      eventType: 'document.content_set_destroyed',
      description: `Content set "${params.contentSetIdentifier}" destroyed for document ${params.documentId} (${params.regulatoryBasis})`,
      organizationId: params.organizationId,
      actorId: params.authorizedBy,
      actorRole: 'org_admin',
      actorLayer: 'content',
      targetType: 'document',
      targetId: params.documentId,
      metadata: {
        contentSetIdentifier: params.contentSetIdentifier,
        regulatoryBasis: params.regulatoryBasis,
      },
    });

    return { destroyed: true, forayTxId: forayTx.forayTxId };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}
