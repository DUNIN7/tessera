// =============================================================================
// TESSERA — Document Versioning Service
//
// "New versions require fresh redaction. System assists by displaying
//  previous markup in distinct color and AI-assisted version comparison.
//  Previous versions and content sets remain intact. Blockchain records
//  link version chains." (§14)
// =============================================================================

import { pool } from '../../db/pool';
import { v4 as uuidv4 } from 'uuid';
import { recordAuditEvent } from '../audit';
import { submitForayTransaction } from '../../foray';
import { VersionChainEntry } from '../../types/system';

/**
 * Register a new version of an existing document. (§14)
 * The new version gets a fresh document record linked to the previous.
 * Previous versions and their content sets remain intact.
 */
export async function registerNewVersion(params: {
  previousDocumentId: string;
  organizationId: string;
  uploadedBy: string;
  title: string;
  originalHash: string;
  filePath: string;
  mimeType: string;
  sizeBytes: number;
}): Promise<{ documentId: string; versionNumber: number }> {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Get previous document and version number
    const prevResult = await client.query(
      `SELECT id, title, version_number, version_chain_id
       FROM documents
       WHERE id = $1 AND organization_id = $2`,
      [params.previousDocumentId, params.organizationId]
    );

    if (prevResult.rows.length === 0) {
      throw new Error('Previous document not found');
    }

    const prev = prevResult.rows[0];
    const newVersion = (prev.version_number || 1) + 1;
    const chainId = prev.version_chain_id || prev.id;
    const docId = uuidv4();

    // Create new document record
    await client.query(
      `INSERT INTO documents
         (id, organization_id, title, status, uploaded_by, original_hash,
          file_path, mime_type, size_bytes, version_number,
          version_chain_id, previous_version_id)
       VALUES ($1, $2, $3, 'intake', $4, $5, $6, $7, $8, $9, $10, $11)`,
      [
        docId, params.organizationId, params.title, params.uploadedBy,
        params.originalHash, params.filePath, params.mimeType,
        params.sizeBytes, newVersion, chainId, params.previousDocumentId,
      ]
    );

    // Ensure the chain ID is set on the original document too
    if (!prev.version_chain_id) {
      await client.query(
        `UPDATE documents SET version_chain_id = $1 WHERE id = $2`,
        [chainId, params.previousDocumentId]
      );
    }

    await client.query('COMMIT');

    // Audit & FORAY
    await recordAuditEvent({
      category: 'arrangement',
      eventType: 'document.version_registered',
      description: `New version ${newVersion} of "${params.title}" registered`,
      organizationId: params.organizationId,
      actorId: params.uploadedBy,
      actorRole: 'redactor',
      actorLayer: 'content',
      targetType: 'document',
      targetId: docId,
      metadata: {
        previousDocumentId: params.previousDocumentId,
        versionNumber: newVersion,
        chainId,
      },
    });

    await submitForayTransaction({
      transactionId: `TESSERA_VERSION_${docId}`,
      transactionType: 'document_version',
      arrangement: {
        documentId: docId,
        previousDocumentId: params.previousDocumentId,
        versionNumber: newVersion,
        chainId,
        originalHash: params.originalHash,
      },
    });

    return { documentId: docId, versionNumber: newVersion };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Get the version chain for a document. (§14)
 * "Blockchain records link version chains."
 */
export async function getVersionChain(
  documentId: string,
  organizationId: string
): Promise<VersionChainEntry[]> {
  // Find the chain ID
  const docResult = await pool.query(
    `SELECT version_chain_id FROM documents
     WHERE id = $1 AND organization_id = $2`,
    [documentId, organizationId]
  );

  if (docResult.rows.length === 0) {
    throw new Error('Document not found');
  }

  const chainId = docResult.rows[0].version_chain_id || documentId;

  // Get all versions in the chain
  const result = await pool.query(
    `SELECT id as document_id, version_number, previous_version_id,
            status, title, original_hash, created_at
     FROM documents
     WHERE (version_chain_id = $1 OR id = $1) AND organization_id = $2
     ORDER BY version_number ASC`,
    [chainId, organizationId]
  );

  return result.rows.map((row: any) => ({
    documentId: row.document_id,
    version: row.version_number || 1,
    previousDocumentId: row.previous_version_id,
    status: row.status,
    title: row.title,
    originalHash: row.original_hash,
    createdAt: row.created_at,
  }));
}

/**
 * Get the previous version's markup session for comparison. (§14)
 * "System assists by displaying previous markup in distinct color."
 */
export async function getPreviousVersionMarkup(
  documentId: string,
  organizationId: string
) {
  const docResult = await pool.query(
    `SELECT previous_version_id FROM documents
     WHERE id = $1 AND organization_id = $2`,
    [documentId, organizationId]
  );

  if (docResult.rows.length === 0 || !docResult.rows[0].previous_version_id) {
    return null;
  }

  const prevDocId = docResult.rows[0].previous_version_id;

  // Get the approved markup session for the previous version
  const sessionResult = await pool.query(
    `SELECT ms.id, ms.operation_count,
            json_agg(json_build_object(
              'contentSet', csa.content_set_identifier,
              'blockId', csa.block_id,
              'startOffset', csa.start_offset,
              'endOffset', csa.end_offset,
              'selectedText', csa.selected_text,
              'page', csa.page_number
            )) as assignments
     FROM markup_sessions ms
     LEFT JOIN content_set_assignments csa ON csa.session_id = ms.id
     WHERE ms.document_id = $1 AND ms.status = 'approved'
     GROUP BY ms.id, ms.operation_count
     ORDER BY ms.created_at DESC LIMIT 1`,
    [prevDocId]
  );

  if (sessionResult.rows.length === 0) return null;

  return {
    previousDocumentId: prevDocId,
    sessionId: sessionResult.rows[0].id,
    operationCount: sessionResult.rows[0].operation_count,
    assignments: sessionResult.rows[0].assignments,
  };
}
