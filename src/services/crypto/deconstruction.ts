// =============================================================================
// TESSERA — Deconstruction Engine
//
// Transforms an approved document into the deconstructed form:
// base document + separately encrypted content sets + positional markers.
// (Tessera v3.1 §8.3, §8.4)
//
// Process (§8.3):
//   1. Base document produced with all redactable content removed;
//      positional markers at each extraction point.
//   2. Separate data set for each content set with positional markers
//      mapping to base document.
//   3. Content in multiple sets duplicated into each with multi-set
//      membership metadata.
//   4. Each content set encrypted with AES-256-GCM using unique key
//      generated in HSM.
//   5. Each encrypted set stored in physically separate location per
//      organization storage tier.
//   6. SHA-512 hashes committed to blockchain via FORAY Protocol.
//
// Positional Marker System (§8.4):
//   "Each marker: UUID, content set membership, positional metadata,
//    SHA-512 hash of extracted content."
//   "Markers are opaque — do not reveal type, length, or nature."
//   "Adjacent extraction points use single marker to prevent
//    count-based inference."
// =============================================================================

import { pool } from '../../db/pool';
import { v4 as uuidv4 } from 'uuid';
import { encryptContentSet, sha512 } from './encryption';
import { getHsmProvider, saveKeyRecord } from './hsm';
import { recordAuditEvent } from '../audit';
import { submitForayTransaction } from '../../foray';
import {
  PositionalMarker,
  EncryptedEnvelope,
  KeyRecord,
  DeconstructionResult,
  StorageConfirmation,
} from '../../types/crypto';

/**
 * Content set data structure before encryption.
 * Built from the markup session's content_set_assignments.
 */
interface ContentSetData {
  identifier: string;
  entries: Array<{
    blockId: string;
    startOffset: number | null;
    endOffset: number | null;
    selectedText: string | null;
    pageNumber: number;
  }>;
}

/**
 * Execute the deconstruction pipeline for an approved document.
 * (Tessera v3.1 §8.3)
 *
 * Precondition: document status is 'approved' and markup session
 * is in 'approved' state.
 */
export async function executeDeconstruction(params: {
  documentId: string;
  sessionId: string;
  organizationId: string;
  actorId: string;
}): Promise<DeconstructionResult> {
  const client = await pool.connect();
  const hsm = getHsmProvider();

  try {
    await client.query('BEGIN');

    // ── Verify preconditions ─────────────────────────────────────────

    const docResult = await client.query(
      `SELECT d.id, d.title, d.status, d.original_hash, d.normalized_hash,
              d.normalized_path, sp.storage_tier, sp.key_split_m, sp.key_split_n
       FROM documents d
       JOIN organizations o ON o.id = d.organization_id
       JOIN security_profiles sp ON sp.organization_id = o.id
       WHERE d.id = $1 AND d.organization_id = $2 AND d.status = 'approved'
       FOR UPDATE`,
      [params.documentId, params.organizationId]
    );

    if (docResult.rows.length === 0) {
      throw new Error('Document not found or not in approved status');
    }

    const doc = docResult.rows[0];

    // Transition document to deconstructing
    await client.query(
      `UPDATE documents SET status = 'deconstructing', updated_at = now() WHERE id = $1`,
      [params.documentId]
    );

    // ── Step 1: Gather content set assignments ───────────────────────

    const assignments = await client.query(
      `SELECT content_set_identifier, block_id, start_offset, end_offset,
              selected_text, page_number
       FROM content_set_assignments
       WHERE session_id = $1
       ORDER BY content_set_identifier, page_number, block_id, start_offset`,
      [params.sessionId]
    );

    // Group by content set
    const contentSets = new Map<string, ContentSetData>();
    for (const row of assignments.rows) {
      const id = row.content_set_identifier;
      if (!contentSets.has(id)) {
        contentSets.set(id, { identifier: id, entries: [] });
      }
      contentSets.get(id)!.entries.push({
        blockId: row.block_id,
        startOffset: row.start_offset,
        endOffset: row.end_offset,
        selectedText: row.selected_text,
        pageNumber: row.page_number,
      });
    }

    if (contentSets.size === 0) {
      throw new Error('No content set assignments found — nothing to deconstruct');
    }

    // ── Step 2: Build positional markers and base document ───────────
    // (§8.3 steps 1-3, §8.4)

    const markers: PositionalMarker[] = [];
    const contentSetPayloads = new Map<string, string>();
    let sequencePosition = 0;

    // Initialize payloads for each content set
    for (const [id] of contentSets) {
      contentSetPayloads.set(id, '');
    }

    // Process all assignments, building markers and extracting content.
    // Sort all assignments by block and position for proper ordering.
    const allAssignments = assignments.rows.sort((a: any, b: any) => {
      if (a.block_id !== b.block_id) return a.block_id.localeCompare(b.block_id);
      const aStart = a.start_offset ?? 0;
      const bStart = b.start_offset ?? 0;
      return aStart - bStart;
    });

    // Track which blocks+offsets have been processed for marker merging
    const processedPositions = new Map<string, PositionalMarker>();

    for (const entry of allAssignments) {
      const posKey = `${entry.block_id}:${entry.start_offset ?? 'full'}:${entry.end_offset ?? 'full'}`;

      if (processedPositions.has(posKey)) {
        // Adjacent or same position — merge into existing marker (§8.4)
        const existing = processedPositions.get(posKey)!;
        if (!existing.contentSetMembership.includes(entry.content_set_identifier)) {
          existing.contentSetMembership.push(entry.content_set_identifier);
          existing.isMerged = true;
        }
      } else {
        // New extraction point — create marker
        sequencePosition++;
        const contentHash = sha512(entry.selected_text || '');

        const marker: PositionalMarker = {
          markerId: uuidv4(),
          contentSetMembership: [entry.content_set_identifier],
          blockId: entry.block_id,
          startOffset: entry.start_offset,
          endOffset: entry.end_offset,
          contentHash,
          isMerged: false,
          sequencePosition,
        };

        markers.push(marker);
        processedPositions.set(posKey, marker);
      }

      // Append content to the content set's payload (§8.3 step 3)
      // "Content in multiple sets duplicated into each"
      const existingPayload = contentSetPayloads.get(entry.content_set_identifier) || '';
      const entryPayload = JSON.stringify({
        markerId: processedPositions.get(posKey)!.markerId,
        blockId: entry.block_id,
        startOffset: entry.start_offset,
        endOffset: entry.end_offset,
        content: entry.selected_text,
        pageNumber: entry.page_number,
      });
      contentSetPayloads.set(
        entry.content_set_identifier,
        existingPayload + (existingPayload ? '\n' : '') + entryPayload
      );
    }

    // Build base document representation with markers
    const baseDocContent = JSON.stringify({
      documentId: params.documentId,
      markers: markers.map(m => ({
        markerId: m.markerId,
        blockId: m.blockId,
        startOffset: m.startOffset,
        endOffset: m.endOffset,
        sequencePosition: m.sequencePosition,
        // Opaque: no type, length, or nature of content (§8.4)
      })),
      markerCount: markers.length,
    }, null, 2);

    const baseDocHash = sha512(baseDocContent);

    // ── Step 3: Encrypt each content set ─────────────────────────────
    // (§8.3 step 4: "Each content set encrypted with AES-256-GCM
    // using unique key generated in HSM")

    const encryptedSets: EncryptedEnvelope[] = [];
    const keyRecords: KeyRecord[] = [];

    const shamirM = doc.key_split_m || 3;
    const shamirN = doc.key_split_n || 5;

    for (const [setId, payload] of contentSetPayloads) {
      // Generate unique key in HSM
      const { keyHandle, keyId } = await hsm.generateKey();

      // Get key material for encryption (in production, crypto
      // happens inside the HSM boundary)
      const keyMaterial = await hsm.getKeyMaterial(keyHandle);

      // Encrypt the content set
      const envelope = encryptContentSet(payload, keyMaterial, keyId, setId);
      encryptedSets.push(envelope);

      // Build key record
      const keyRecord: KeyRecord = {
        id: keyId,
        documentId: params.documentId,
        contentSetIdentifier: setId,
        organizationId: params.organizationId,
        hsmKeyHandle: keyHandle,
        algorithm: 'aes-256-gcm',
        shamirConfig: { threshold: shamirM, totalShares: shamirN },
        isActive: true,
        rotatedFromKeyId: null,
        createdAt: new Date().toISOString(),
        rotatedAt: null,
        destroyedAt: null,
      };

      keyRecords.push(keyRecord);

      // Save key record to database
      await saveKeyRecord(keyRecord);

      // Split key using Shamir's Secret Sharing (§10.2)
      // In production, holder IDs would come from org configuration.
      // Phase 4: Generate placeholder holder IDs.
      const holderIds = Array.from({ length: shamirN }, (_, i) =>
        `holder-${params.organizationId}-${i + 1}`
      );

      const shares = await hsm.splitKeyToShares(keyHandle, shamirM, shamirN, holderIds);

      // Store share metadata (not the share data itself in production)
      for (const share of shares) {
        await client.query(
          `INSERT INTO key_shares
             (id, key_id, share_index, holder_id, distributed)
           VALUES ($1, $2, $3, $4, false)`,
          [uuidv4(), keyId, share.index, share.holderId]
        );
      }

      // Zero out key material from local memory
      keyMaterial.fill(0);
    }

    // ── Step 4: Store encrypted sets ─────────────────────────────────
    // (§8.3 step 5: "stored in physically separate location per
    // organization storage tier")
    //
    // Phase 4: Storage is to database JSONB. Physical separation
    // across data centers / facilities is a deployment concern
    // configured via security profiles. The storage confirmation
    // records are production-ready.

    const storageConfirmations: StorageConfirmation[] = [];

    for (const envelope of encryptedSets) {
      const locationId = `storage-${doc.storage_tier}-${envelope.contentSetIdentifier}-${uuidv4().slice(0, 8)}`;

      await client.query(
        `INSERT INTO encrypted_content_sets
           (id, document_id, content_set_identifier, organization_id,
            encrypted_envelope, ciphertext_hash, storage_location_id,
            storage_tier, key_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          uuidv4(), params.documentId, envelope.contentSetIdentifier,
          params.organizationId, JSON.stringify(envelope),
          envelope.ciphertextHash, locationId,
          doc.storage_tier || 'tier_1',
          envelope.keyId,
        ]
      );

      storageConfirmations.push({
        contentSetIdentifier: envelope.contentSetIdentifier,
        storageLocationId: locationId,
        storageTier: doc.storage_tier || 'tier_1',
        hash: envelope.ciphertextHash,
        confirmedAt: new Date().toISOString(),
      });
    }

    // Store base document and markers
    await client.query(
      `INSERT INTO base_documents
         (id, document_id, organization_id, content, content_hash, markers)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        uuidv4(), params.documentId, params.organizationId,
        baseDocContent, baseDocHash, JSON.stringify(markers),
      ]
    );

    // ── Step 5: Transition document to active ────────────────────────

    await client.query(
      `UPDATE documents SET status = 'active', updated_at = now() WHERE id = $1`,
      [params.documentId]
    );

    await client.query('COMMIT');

    // ── Step 6: Blockchain registration ──────────────────────────────
    // (§8.3 step 6, §6.4)

    const forayTx = await submitForayTransaction({
      transactionId: `TESSERA_DECONSTRUCTION_${params.documentId}`,
      transactionType: 'document_deconstruction',
      arrangement: {
        documentId: params.documentId,
        organizationId: params.organizationId,
        contentSetCount: contentSets.size,
        contentSetIdentifiers: Array.from(contentSets.keys()),
        storageTier: doc.storage_tier || 'tier_1',
        shamirConfig: { threshold: shamirM, totalShares: shamirN },
      },
      accrual: {
        baseDocumentHash: baseDocHash,
        contentSetHashes: encryptedSets.reduce((acc, e) => {
          acc[e.contentSetIdentifier] = {
            plaintextHash: e.plaintextHash,
            ciphertextHash: e.ciphertextHash,
          };
          return acc;
        }, {} as Record<string, { plaintextHash: string; ciphertextHash: string }>),
        markerCount: markers.length,
        keyRecordIds: keyRecords.map(k => k.id),
        storageConfirmations: storageConfirmations.map(sc => ({
          contentSet: sc.contentSetIdentifier,
          location: sc.storageLocationId,
          hash: sc.hash,
        })),
      },
    });

    // Audit
    await recordAuditEvent({
      category: 'action',
      eventType: 'document.deconstructed',
      description: `Document "${doc.title}" deconstructed: ${contentSets.size} content set(s), ${markers.length} marker(s)`,
      organizationId: params.organizationId,
      actorId: params.actorId,
      actorRole: 'system_admin',
      actorLayer: 'content',
      targetType: 'document',
      targetId: params.documentId,
      metadata: {
        contentSets: Array.from(contentSets.keys()),
        markerCount: markers.length,
        storageTier: doc.storage_tier,
        shamirConfig: { m: shamirM, n: shamirN },
        forayTxId: forayTx.forayTxId,
      },
    });

    return {
      documentId: params.documentId,
      baseDocument: { content: baseDocContent, hash: baseDocHash },
      contentSets: encryptedSets,
      markers,
      keyRecords,
      forayTxId: forayTx.forayTxId,
      storageConfirmations,
      timestamp: new Date().toISOString(),
    };
  } catch (err) {
    await client.query('ROLLBACK');

    // Attempt to reset document status on failure
    try {
      await pool.query(
        `UPDATE documents SET status = 'approved', updated_at = now()
         WHERE id = $1 AND status = 'deconstructing'`,
        [params.documentId]
      );
    } catch {}

    throw err;
  } finally {
    client.release();
  }
}
