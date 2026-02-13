// =============================================================================
// TESSERA — Export & Watermarking Service
//
// Document export with mandatory watermarking. (§9.3, §10.5)
//
// "Read-only views within application. Export permitted per organization
//  security profile. Exported documents watermarked. Export events
//  recorded on blockchain." (§9.3)
//
// "Invisible watermarks encoding: viewer identity, access level,
//  timestamp, document version, reconstruction event ID.
//  Survives print, scan, screenshot. Mandatory for exports;
//  configurable for in-app viewing." (§10.5)
//
// Phase 5: Implements watermark payload generation and export event
// recording. Actual invisible watermark embedding (steganographic)
// requires evaluation of watermarking technology (§17 Outstanding Items).
// The payload is embedded as metadata; production watermarking library
// integration is deferred.
// =============================================================================

import { pool } from '../../db/pool';
import { v4 as uuidv4 } from 'uuid';
import { sha512 } from '../crypto/encryption';
import { recordAuditEvent } from '../audit';
import { submitForayTransaction } from '../../foray';
import { ExportRequest, ExportResult, WatermarkPayload } from '../../types/system';

/**
 * Export a reconstructed document with mandatory watermarking. (§9.3)
 *
 * Preconditions:
 *   - Valid reconstruction event exists
 *   - Viewer has export permission per security profile
 *   - Organization security profile permits export at this access level
 */
export async function exportDocument(request: ExportRequest): Promise<ExportResult> {
  const exportEventId = uuidv4();

  // ── Verify reconstruction event exists ─────────────────────────────

  const reconResult = await pool.query(
    `SELECT re.id, re.document_id, re.viewer_id, re.access_level_id,
            re.content_sets_used, re.content_sets_redacted, re.marker_width,
            d.title, d.version_number,
            u.display_name as viewer_name,
            al.name as access_level_name
     FROM reconstruction_events re
     JOIN documents d ON d.id = re.document_id
     JOIN users u ON u.id = re.viewer_id
     LEFT JOIN access_levels al ON al.id = re.access_level_id
     WHERE re.id = $1 AND re.organization_id = $2 AND re.viewer_id = $3`,
    [request.reconstructionEventId, request.organizationId, request.viewerId]
  );

  if (reconResult.rows.length === 0) {
    throw new Error('Reconstruction event not found or access denied');
  }

  const recon = reconResult.rows[0];

  // ── Check export permission in security profile ────────────────────

  const profileResult = await pool.query(
    `SELECT export_permitted FROM security_profiles WHERE organization_id = $1`,
    [request.organizationId]
  );

  if (profileResult.rows.length > 0 && !profileResult.rows[0].export_permitted) {
    throw new Error('Export not permitted by organization security profile');
  }

  // ── Generate watermark payload (§10.5) ─────────────────────────────

  const watermarkPayload: WatermarkPayload = {
    viewerId: request.viewerId,
    viewerName: recon.viewer_name,
    accessLevelId: request.accessLevelId,
    accessLevelName: recon.access_level_name || 'Unknown',
    documentId: request.documentId,
    documentVersion: recon.version_number || 1,
    reconstructionEventId: request.reconstructionEventId,
    exportEventId,
    timestamp: new Date().toISOString(),
    organizationId: request.organizationId,
  };

  // ── Build exported content ─────────────────────────────────────────
  // Phase 5: Generates a structured export with embedded watermark
  // metadata. Production export would render to PDF/HTML with
  // steganographic invisible watermark.

  const exportContent = JSON.stringify({
    tessera: {
      exportVersion: '1.0',
      format: request.format,
      exportEventId,
      documentTitle: recon.title,
      accessLevel: recon.access_level_name,
      markerWidth: recon.marker_width,
      contentSetsVisible: JSON.parse(recon.content_sets_used || '[]'),
      contentSetsRedacted: JSON.parse(recon.content_sets_redacted || '[]'),
      exportedAt: watermarkPayload.timestamp,
    },
    watermark: {
      // In production, this would be steganographically embedded.
      // Phase 5: Included as metadata for traceability.
      encoded: Buffer.from(JSON.stringify(watermarkPayload)).toString('base64'),
      algorithm: 'metadata-embedded', // TODO: steganographic embedding
    },
    content: {
      reconstructionEventId: request.reconstructionEventId,
      note: 'Reconstructed content would be rendered here in the target format.',
    },
  }, null, 2);

  const contentHash = sha512(exportContent);

  // ── Record export event ────────────────────────────────────────────

  await pool.query(
    `INSERT INTO export_events
       (id, document_id, organization_id, viewer_id, access_level_id,
        reconstruction_event_id, format, content_hash, watermark_payload)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [
      exportEventId, request.documentId, request.organizationId,
      request.viewerId, request.accessLevelId,
      request.reconstructionEventId, request.format,
      contentHash, JSON.stringify(watermarkPayload),
    ]
  );

  // ── Audit & FORAY ─────────────────────────────────────────────────

  await recordAuditEvent({
    category: 'action',
    eventType: 'document.exported',
    description: `Document "${recon.title}" exported as ${request.format} by ${recon.viewer_name}`,
    organizationId: request.organizationId,
    actorId: request.viewerId,
    actorRole: 'viewer',
    actorLayer: 'content',
    targetType: 'document',
    targetId: request.documentId,
    metadata: {
      exportEventId,
      format: request.format,
      accessLevelId: request.accessLevelId,
      reconstructionEventId: request.reconstructionEventId,
      watermarked: true,
      contentHash,
    },
  });

  await submitForayTransaction({
    transactionId: `TESSERA_EXPORT_${exportEventId}`,
    transactionType: 'document_export',
    action: {
      exportEventId,
      documentId: request.documentId,
      viewerId: request.viewerId,
      accessLevelId: request.accessLevelId,
      format: request.format,
      contentHash,
      watermarked: true,
      timestamp: watermarkPayload.timestamp,
    },
  });

  return {
    exportEventId,
    documentId: request.documentId,
    format: request.format,
    watermarked: true,
    watermarkPayload,
    content: exportContent,
    contentHash,
    exportedAt: watermarkPayload.timestamp,
  };
}

/**
 * Record a viewing session for behavioral audit. (§11.2 Viewing level)
 */
export async function recordViewingSession(params: {
  reconstructionEventId: string;
  documentId: string;
  viewerId: string;
  accessLevelId: string;
  organizationId: string;
  pagesViewed: number[];
  durationSeconds: number;
  navigationEvents: Array<{ action: string; page?: number; timestamp: string }>;
}): Promise<{ sessionId: string }> {
  const sessionId = uuidv4();

  await pool.query(
    `INSERT INTO viewing_sessions
       (id, reconstruction_event_id, document_id, viewer_id,
        access_level_id, organization_id, pages_viewed,
        duration_seconds, navigation_events)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [
      sessionId, params.reconstructionEventId, params.documentId,
      params.viewerId, params.accessLevelId, params.organizationId,
      JSON.stringify(params.pagesViewed), params.durationSeconds,
      JSON.stringify(params.navigationEvents),
    ]
  );

  await recordAuditEvent({
    category: 'action',
    eventType: 'document.viewed',
    description: `Viewing session: ${params.pagesViewed.length} pages, ${params.durationSeconds}s`,
    organizationId: params.organizationId,
    actorId: params.viewerId,
    actorRole: 'viewer',
    actorLayer: 'content',
    targetType: 'document',
    targetId: params.documentId,
    metadata: {
      viewingSessionId: sessionId,
      pagesViewed: params.pagesViewed,
      durationSeconds: params.durationSeconds,
    },
  });

  return { sessionId };
}
