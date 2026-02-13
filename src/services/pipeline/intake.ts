// =============================================================================
// TESSERA — Intake Pipeline Orchestrator
//
// Coordinates the document intake pipeline: upload → validate →
// normalize → scan → register. (Tessera v3.1 §6)
//
// Pipeline flow:
//   1. File received via multipart upload
//   2. Format validation (§6.1) — MIME type, magic bytes, unsupported content
//   3. Hash computation (§6.4) — SHA-512 of original
//   4. Normalization (§6.2) — convert to intermediate format, hash normalized
//   5. Coded content scan (§6.3) — mandatory gate, all five detection categories
//   6. Registration — document record created, hashes committed via FORAY
//   7. Status set to intake_cleared or intake_flagged
//
// "No document proceeds to markup until coded content scanning is complete."
// =============================================================================

import { pool } from '../../db/pool';
import { v4 as uuidv4 } from 'uuid';
import { validateFormat, computeFileHash } from './validation';
import { normalizeDocument } from './normalization';
import { scanForCodedContent } from './stego-scanner';
import { recordAuditEvent } from '../audit';
import { submitForayTransaction } from '../../foray';
import {
  IntakePipelineResult,
  StegoScanResult,
  ScanDisposition,
} from '../../types/pipeline';
import { UserRole, RoleLayer } from '../../types/roles';

/**
 * Execute the full intake pipeline for an uploaded document.
 * Returns the pipeline result including document ID and status.
 *
 * Called from the document upload route after file is saved to temp storage.
 */
export async function executeIntakePipeline(params: {
  filePath: string;
  originalFilename: string;
  declaredMimeType: string;
  title: string;
  organizationId: string;
  actorId: string;
  actorRole: UserRole;
}): Promise<IntakePipelineResult> {
  const errors: string[] = [];
  const documentId = uuidv4();

  // ── Step 1: Format Validation (§6.1) ─────────────────────────────────

  const validation = await validateFormat(
    params.filePath,
    params.declaredMimeType,
    params.originalFilename
  );

  if (!validation.valid) {
    // Record rejection in audit trail
    await recordAuditEvent({
      category: 'action',
      eventType: 'document.intake_rejected',
      description: `Document "${params.title}" rejected at format validation: ${validation.errors.join('; ')}`,
      organizationId: params.organizationId,
      actorId: params.actorId,
      actorRole: params.actorRole,
      actorLayer: 'content',
      targetType: 'document',
      targetId: documentId,
      metadata: {
        filename: params.originalFilename,
        mimeType: params.declaredMimeType,
        errors: validation.errors,
      },
    });

    return {
      documentId,
      originalHash: '',
      validation,
      normalization: null,
      stegoScan: null,
      finalStatus: 'rejected',
      errors: validation.errors,
    };
  }

  // ── Step 2: Hash Original File (§6.4) ────────────────────────────────

  const originalHash = computeFileHash(params.filePath);

  // ── Step 3: Create Document Record ───────────────────────────────────

  await pool.query(
    `INSERT INTO documents
       (id, organization_id, title, original_filename, mime_type,
        original_size_bytes, original_hash, status)
     VALUES ($1, $2, $3, $4, $5, $6, $7, 'intake')`,
    [
      documentId,
      params.organizationId,
      params.title,
      params.originalFilename,
      validation.mimeType,
      validation.sizeBytes,
      originalHash,
    ]
  );

  // Audit: intake started
  await recordAuditEvent({
    category: 'arrangement',
    eventType: 'document.intake',
    description: `Document "${params.title}" registered at intake`,
    organizationId: params.organizationId,
    actorId: params.actorId,
    actorRole: params.actorRole,
    actorLayer: 'content',
    targetType: 'document',
    targetId: documentId,
    metadata: {
      filename: params.originalFilename,
      mimeType: validation.mimeType,
      sizeBytes: validation.sizeBytes,
      originalHash,
      unsupportedFlags: validation.unsupportedFlags,
    },
  });

  // ── Step 4: Normalization (§6.2) ─────────────────────────────────────

  const normalization = await normalizeDocument(
    params.filePath,
    originalHash,
    validation.mimeType,
    params.originalFilename
  );

  if (normalization.success && normalization.normalizedHash) {
    // Update document with normalized hash and path
    await pool.query(
      `UPDATE documents
       SET normalized_hash = $1, normalized_path = $2, updated_at = now()
       WHERE id = $3`,
      [normalization.normalizedHash, normalization.normalizedPath, documentId]
    );

    // Audit: normalization complete
    await recordAuditEvent({
      category: 'accrual',
      eventType: 'document.normalized',
      description: `Document "${params.title}" normalized. Hash chain: original → normalized.`,
      organizationId: params.organizationId,
      actorId: params.actorId,
      actorRole: params.actorRole,
      actorLayer: 'content',
      targetType: 'document',
      targetId: documentId,
      metadata: {
        normalizedHash: normalization.normalizedHash,
        pageCount: normalization.metadata.pageCount,
        wordCount: normalization.metadata.wordCount,
        hasImages: normalization.metadata.hasImages,
        hasTables: normalization.metadata.hasTables,
      },
    });
  } else {
    errors.push(...normalization.errors);
  }

  // ── Step 5: Coded Content / Stego Scan (§6.3) — MANDATORY GATE ──────

  const stegoScan = await scanForCodedContent(params.filePath, validation.mimeType);

  // Store scan result on document
  await pool.query(
    `UPDATE documents SET stego_scan_result = $1, updated_at = now() WHERE id = $2`,
    [JSON.stringify(stegoScan), documentId]
  );

  // Audit: scan complete
  await recordAuditEvent({
    category: 'accrual',
    eventType: 'document.stego_scan_complete',
    description: `Coded content scan complete for "${params.title}". Severity: ${stegoScan.overallSeverity}. Findings: ${stegoScan.findings.length}.`,
    organizationId: params.organizationId,
    actorId: params.actorId,
    actorRole: params.actorRole,
    actorLayer: 'content',
    targetType: 'document',
    targetId: documentId,
    metadata: {
      overallSeverity: stegoScan.overallSeverity,
      findingCount: stegoScan.findings.length,
      findingSummary: stegoScan.findings.map(f => ({
        category: f.category,
        severity: f.severity,
        description: f.description,
      })),
      scannerVersion: stegoScan.scannerVersion,
    },
  });

  // ── Step 6: Determine Status ─────────────────────────────────────────

  const hasFlagged = stegoScan.findings.some(
    f => f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium'
  );
  const hasUnsupported = validation.unsupportedFlags.length > 0;
  const needsReview = hasFlagged || hasUnsupported;

  const finalStatus = needsReview ? 'intake_flagged' : 'intake_cleared';

  await pool.query(
    `UPDATE documents SET status = $1, updated_at = now() WHERE id = $2`,
    [finalStatus, documentId]
  );

  // ── Step 7: FORAY Registration (§6.4) ────────────────────────────────

  const forayTx = await submitForayTransaction({
    transactionId: `TESSERA_INTAKE_${documentId}`,
    transactionType: 'document_intake',
    arrangement: {
      documentId,
      organizationId: params.organizationId,
      title: params.title,
      originalHash,
      normalizedHash: normalization.normalizedHash,
      mimeType: validation.mimeType,
      sizeBytes: validation.sizeBytes,
      scanClearance: finalStatus,
    },
    accrual: {
      originalHash,
      normalizedHash: normalization.normalizedHash,
      scanResult: {
        overallSeverity: stegoScan.overallSeverity,
        findingCount: stegoScan.findings.length,
        scannerVersion: stegoScan.scannerVersion,
      },
    },
  });

  // Update document with FORAY TX reference
  await pool.query(
    `UPDATE documents SET foray_intake_tx_id = $1, updated_at = now() WHERE id = $2`,
    [forayTx.forayTxId, documentId]
  );

  return {
    documentId,
    originalHash,
    validation,
    normalization,
    stegoScan,
    finalStatus: finalStatus as 'intake_cleared' | 'intake_flagged',
    errors,
  };
}

/**
 * Admin disposition for a flagged document. (Tessera v3.1 §6.3)
 * "Admin decides: proceed (accepting risk), sanitize flagged elements, or reject."
 */
export async function resolveIntakeFlag(params: {
  documentId: string;
  disposition: ScanDisposition;
  adminId: string;
  notes: string;
  organizationId: string;
}): Promise<{ newStatus: string }> {
  // Fetch current scan result
  const docResult = await pool.query(
    `SELECT stego_scan_result, status, title FROM documents WHERE id = $1 AND organization_id = $2`,
    [params.documentId, params.organizationId]
  );

  if (docResult.rows.length === 0) {
    throw new Error('Document not found');
  }

  const doc = docResult.rows[0];
  if (doc.status !== 'intake_flagged') {
    throw new Error(`Document status is "${doc.status}", not "intake_flagged"`);
  }

  // Update scan result with disposition
  const scanResult: StegoScanResult = doc.stego_scan_result;
  scanResult.disposition = params.disposition;
  scanResult.dispositionBy = params.adminId;
  scanResult.dispositionAt = new Date().toISOString();
  scanResult.dispositionNotes = params.notes;

  let newStatus: string;
  switch (params.disposition) {
    case 'proceed':
      newStatus = 'intake_cleared';
      break;
    case 'sanitize':
      // TODO: sanitization pipeline strips flagged elements
      newStatus = 'intake_cleared';
      break;
    case 'reject':
      newStatus = 'destroyed'; // Rejected documents are removed
      break;
    default:
      throw new Error(`Invalid disposition: ${params.disposition}`);
  }

  await pool.query(
    `UPDATE documents
     SET status = $1, stego_scan_result = $2, updated_at = now()
     WHERE id = $3`,
    [newStatus, JSON.stringify(scanResult), params.documentId]
  );

  // Audit: disposition recorded
  await recordAuditEvent({
    category: 'action',
    eventType: 'document.intake_disposition',
    description: `Admin resolved intake flag for "${doc.title}": ${params.disposition}`,
    organizationId: params.organizationId,
    actorId: params.adminId,
    actorRole: 'org_admin',
    actorLayer: 'content',
    targetType: 'document',
    targetId: params.documentId,
    metadata: {
      disposition: params.disposition,
      notes: params.notes,
      previousSeverity: scanResult.overallSeverity,
      findingCount: scanResult.findings.length,
    },
  });

  // FORAY: record disposition
  await submitForayTransaction({
    transactionId: `TESSERA_DISPOSITION_${params.documentId}`,
    transactionType: 'intake_disposition',
    action: {
      documentId: params.documentId,
      disposition: params.disposition,
      adminId: params.adminId,
      timestamp: new Date().toISOString(),
    },
  });

  return { newStatus };
}
