// =============================================================================
// TESSERA — Document Pipeline Types
//
// Types for the document intake pipeline: upload, validation,
// normalization, coded content scanning, and registration.
// (Tessera v3.1 §6)
// =============================================================================

/**
 * Supported MIME types for document intake. (Tessera v3.1 §6.1)
 * Documents outside this list are rejected at validation.
 */
export const SUPPORTED_MIME_TYPES: Record<string, { extensions: string[]; category: string }> = {
  // PDF (including scanned/OCR)
  'application/pdf':                                              { extensions: ['.pdf'],  category: 'pdf' },

  // Microsoft Word
  'application/msword':                                           { extensions: ['.doc'],  category: 'word' },
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
                                                                  { extensions: ['.docx'], category: 'word' },

  // Microsoft Excel
  'application/vnd.ms-excel':                                     { extensions: ['.xls'],  category: 'excel' },
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':
                                                                  { extensions: ['.xlsx'], category: 'excel' },

  // Microsoft PowerPoint
  'application/vnd.ms-powerpoint':                                { extensions: ['.ppt'],  category: 'powerpoint' },
  'application/vnd.openxmlformats-officedocument.presentationml.presentation':
                                                                  { extensions: ['.pptx'], category: 'powerpoint' },

  // HTML
  'text/html':                                                    { extensions: ['.html', '.htm'], category: 'html' },

  // Plain text and RTF
  'text/plain':                                                   { extensions: ['.txt'],  category: 'text' },
  'application/rtf':                                              { extensions: ['.rtf'],  category: 'rtf' },
  'text/rtf':                                                     { extensions: ['.rtf'],  category: 'rtf' },

  // Image formats
  'image/png':                                                    { extensions: ['.png'],  category: 'image' },
  'image/jpeg':                                                   { extensions: ['.jpg', '.jpeg'], category: 'image' },
  'image/tiff':                                                   { extensions: ['.tiff', '.tif'], category: 'image' },
  'image/bmp':                                                    { extensions: ['.bmp'],  category: 'image' },
};

/**
 * Content that must be flagged/stripped at intake. (Tessera v3.1 §6.1)
 * Documents containing these elements are flagged; admin decides to
 * proceed (with unsupported elements stripped) or reject.
 */
export const UNSUPPORTED_CONTENT_FLAGS = [
  'embedded_macros',      // VBA macros in Office documents
  'javascript',           // JS in PDF or HTML
  'drm_protection',       // Digital rights management
  'embedded_video',       // Video content in documents
  'password_protection',  // Encrypted/password-protected files
  'embedded_executables', // Executable content in any format
] as const;

export type UnsupportedContentFlag = typeof UNSUPPORTED_CONTENT_FLAGS[number];

/**
 * Result of format validation. (Tessera v3.1 §6.1)
 */
export interface FormatValidationResult {
  valid: boolean;
  mimeType: string;
  detectedMimeType: string;
  category: string | null;
  fileExtension: string;
  sizeBytes: number;
  unsupportedFlags: UnsupportedContentFlag[];
  errors: string[];
}

/**
 * Severity levels for coded content / stego scan findings.
 * (Tessera v3.1 §6.3)
 */
export type ScanSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * Individual finding from coded content / stego scan.
 * (Tessera v3.1 §6.3)
 */
export interface ScanFinding {
  /** Unique finding ID */
  id: string;

  /** Category of detection */
  category:
    | 'unicode_anomaly'       // Homoglyphs, zero-width chars, directional overrides
    | 'encoding_pattern'      // Acrostics, first-letter patterns, statistical anomalies
    | 'image_steganography'   // LSB analysis, DCT coefficient anomalies
    | 'metadata_payload'      // Hidden content in metadata, custom XML, comments
    | 'structural_anomaly';   // Invisible text layers, hidden rows/columns, off-canvas

  /** Severity rating */
  severity: ScanSeverity;

  /** Human-readable description of what was detected */
  description: string;

  /** Location within the document (page, paragraph, cell, etc.) */
  location: string;

  /** Specific indicators that triggered the finding */
  indicators: string[];

  /** Confidence score (0.0 - 1.0) */
  confidence: number;
}

/**
 * Admin disposition for flagged documents. (Tessera v3.1 §6.3)
 */
export type ScanDisposition = 'proceed' | 'sanitize' | 'reject';

/**
 * Complete result of coded content / steganographic scan.
 * Stored in documents.stego_scan_result as JSONB.
 * (Tessera v3.1 §6.3: "This is a mandatory intake gate.")
 */
export interface StegoScanResult {
  /** Whether the scan has completed */
  scanComplete: boolean;

  /** When the scan was performed */
  scannedAt: string;

  /** Overall severity (highest finding severity, or 'info' if clean) */
  overallSeverity: ScanSeverity;

  /** Individual findings */
  findings: ScanFinding[];

  /** Admin disposition (set after review of findings) */
  disposition?: ScanDisposition;

  /** Who made the disposition decision */
  dispositionBy?: string;

  /** When the disposition was decided */
  dispositionAt?: string;

  /** Admin notes on the disposition */
  dispositionNotes?: string;

  /** Scanner version / model used */
  scannerVersion: string;
}

/**
 * Result of document normalization. (Tessera v3.1 §6.2)
 */
export interface NormalizationResult {
  /** Whether normalization succeeded */
  success: boolean;

  /** Path to the normalized intermediate representation */
  normalizedPath: string | null;

  /** SHA-512 hash of the normalized representation */
  normalizedHash: string | null;

  /** Metadata extracted during normalization */
  metadata: {
    pageCount?: number;
    wordCount?: number;
    hasImages: boolean;
    hasTables: boolean;
    languages?: string[];
  };

  /** Errors encountered during normalization */
  errors: string[];
}

/**
 * Complete intake pipeline result.
 * Aggregates validation, normalization, and scan results.
 */
export interface IntakePipelineResult {
  documentId: string;
  originalHash: string;
  validation: FormatValidationResult;
  normalization: NormalizationResult | null;
  stegoScan: StegoScanResult | null;
  finalStatus: 'intake_cleared' | 'intake_flagged' | 'rejected';
  errors: string[];
}
