// =============================================================================
// TESSERA — Phase 5+6 Types
//
// Types for export/watermarking (§9.3, §10.5), document versioning (§14),
// data retention/destruction (§12), and system health monitoring.
// =============================================================================

// ── Export & Watermarking (§9.3, §10.5) ────────────────────────────────

/**
 * Watermark payload embedded in exported documents. (§10.5)
 * "Invisible watermarks encoding: viewer identity, access level,
 *  timestamp, document version, reconstruction event ID.
 *  Survives print, scan, screenshot."
 */
export interface WatermarkPayload {
  viewerId: string;
  viewerName: string;
  accessLevelId: string;
  accessLevelName: string;
  documentId: string;
  documentVersion: number;
  reconstructionEventId: string;
  exportEventId: string;
  timestamp: string;
  organizationId: string;
}

/**
 * Export request. (§9.3)
 * "Export permitted per organization security profile."
 */
export interface ExportRequest {
  documentId: string;
  reconstructionEventId: string;
  viewerId: string;
  accessLevelId: string;
  organizationId: string;
  format: 'pdf' | 'html' | 'txt';
}

/**
 * Export result with watermark confirmation.
 */
export interface ExportResult {
  exportEventId: string;
  documentId: string;
  format: string;
  watermarked: boolean;
  watermarkPayload: WatermarkPayload;
  content: string;
  contentHash: string;
  exportedAt: string;
}

// ── Document Versioning (§14) ──────────────────────────────────────────

/**
 * Version chain link. (§14)
 * "Previous versions and content sets remain intact.
 *  Blockchain records link version chains."
 */
export interface VersionChainEntry {
  documentId: string;
  version: number;
  previousDocumentId: string | null;
  status: string;
  title: string;
  originalHash: string;
  createdAt: string;
}

// ── Viewing Session Tracking (§11.2) ───────────────────────────────────

/**
 * Viewing session for behavioral audit. (§11.2 Viewing level)
 * "User, document, access level, timestamp, pages viewed,
 *  duration, navigation"
 */
export interface ViewingSession {
  id: string;
  reconstructionEventId: string;
  documentId: string;
  viewerId: string;
  accessLevelId: string;
  organizationId: string;
  startedAt: string;
  endedAt: string | null;
  durationSeconds: number | null;
  pagesViewed: number[];
  navigationEvents: Array<{
    action: 'page_view' | 'scroll' | 'zoom' | 'search';
    page?: number;
    timestamp: string;
  }>;
}

// ── Data Retention (§12) ───────────────────────────────────────────────

/**
 * Retention policy for a document. (§12.1)
 */
export interface RetentionPolicy {
  documentId: string;
  regulatoryFloor: string | null;        // Minimum from regulation
  regulatoryFloorDate: string | null;     // Earliest allowed destruction
  organizationPolicy: string | null;      // May extend but never shorten
  organizationPolicyDate: string | null;
  effectiveRetentionDate: string | null;  // The later of the two
  hasLegalHold: boolean;
  legalHoldReason: string | null;
}

/**
 * Destruction request. (§12.2)
 */
export interface DestructionRequest {
  documentId: string;
  organizationId: string;
  authorizedBy: string;
  reason: string;
  regulatoryClearance: boolean;
}

/**
 * Destruction result.
 */
export interface DestructionResult {
  documentId: string;
  contentSetsDestroyed: string[];
  keysDestroyed: string[];
  backupsDestroyed: boolean;
  forayTxId: string;
  destroyedAt: string;
}

// ── System Health ──────────────────────────────────────────────────────

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  version: string;
  uptime: number;
  checks: {
    database: { status: string; latencyMs: number };
    foray: { status: string; latencyMs: number };
    hsm: { status: string };
    storage: { status: string };
  };
  timestamp: string;
}
