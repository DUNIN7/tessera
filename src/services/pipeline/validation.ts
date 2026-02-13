// =============================================================================
// TESSERA — Format Validation Service
//
// Validates uploaded documents against supported formats (§6.1),
// detects unsupported content (macros, JS, DRM, etc.), and performs
// basic integrity checks before normalization.
//
// Tessera v3.1 §6.1: "Documents with embedded macros, JavaScript, DRM,
// embedded video, or password protection are flagged at intake."
// =============================================================================

import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import {
  SUPPORTED_MIME_TYPES,
  UnsupportedContentFlag,
  FormatValidationResult,
} from '../../types/pipeline';

// Magic byte signatures for file type detection.
// We verify the declared MIME type matches actual file content
// to prevent MIME spoofing attacks.
const MAGIC_SIGNATURES: Array<{
  bytes: number[];
  offset: number;
  mime: string[];
}> = [
  // PDF
  { bytes: [0x25, 0x50, 0x44, 0x46],         offset: 0, mime: ['application/pdf'] },
  // ZIP-based (docx, xlsx, pptx, etc.)
  { bytes: [0x50, 0x4B, 0x03, 0x04],         offset: 0, mime: [
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  ]},
  // Legacy Office (doc, xls, ppt) — Compound File Binary Format
  { bytes: [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], offset: 0, mime: [
    'application/msword',
    'application/vnd.ms-excel',
    'application/vnd.ms-powerpoint',
  ]},
  // PNG
  { bytes: [0x89, 0x50, 0x4E, 0x47],         offset: 0, mime: ['image/png'] },
  // JPEG
  { bytes: [0xFF, 0xD8, 0xFF],               offset: 0, mime: ['image/jpeg'] },
  // TIFF (little-endian)
  { bytes: [0x49, 0x49, 0x2A, 0x00],         offset: 0, mime: ['image/tiff'] },
  // TIFF (big-endian)
  { bytes: [0x4D, 0x4D, 0x00, 0x2A],         offset: 0, mime: ['image/tiff'] },
  // BMP
  { bytes: [0x42, 0x4D],                     offset: 0, mime: ['image/bmp'] },
  // RTF
  { bytes: [0x7B, 0x5C, 0x72, 0x74, 0x66],  offset: 0, mime: ['application/rtf', 'text/rtf'] },
];

/**
 * Detect the actual file type from magic bytes.
 * Returns possible MIME types, or null if unrecognized.
 */
function detectMimeFromBytes(buffer: Buffer): string[] | null {
  for (const sig of MAGIC_SIGNATURES) {
    if (buffer.length < sig.offset + sig.bytes.length) continue;
    const match = sig.bytes.every((b, i) => buffer[sig.offset + i] === b);
    if (match) return sig.mime;
  }
  return null;
}

/**
 * Check for unsupported content indicators in file content.
 * (Tessera v3.1 §6.1)
 *
 * This is a surface-level scan. Deeper analysis happens during
 * normalization and stego scanning.
 */
function detectUnsupportedContent(
  buffer: Buffer,
  declaredMime: string
): UnsupportedContentFlag[] {
  const flags: UnsupportedContentFlag[] = [];
  const content = buffer.toString('utf-8', 0, Math.min(buffer.length, 100000));

  // Check for VBA macros in Office documents
  if (declaredMime.includes('ms-') || declaredMime.includes('openxmlformats')) {
    // vbaProject.bin in ZIP-based Office or VBA signature in legacy
    if (content.includes('vbaProject') || content.includes('_VBA_PROJECT')) {
      flags.push('embedded_macros');
    }
  }

  // Check for JavaScript in PDF or HTML
  if (declaredMime === 'application/pdf') {
    if (content.includes('/JavaScript') || content.includes('/JS ')) {
      flags.push('javascript');
    }
  }
  if (declaredMime === 'text/html') {
    if (/<script[\s>]/i.test(content)) {
      flags.push('javascript');
    }
  }

  // Check for encryption / password protection in PDF
  if (declaredMime === 'application/pdf') {
    if (content.includes('/Encrypt')) {
      flags.push('password_protection');
    }
  }

  // Check for encrypted ZIP-based Office docs (EncryptedPackage)
  if (declaredMime.includes('openxmlformats')) {
    if (content.includes('EncryptedPackage') || content.includes('encryption')) {
      flags.push('password_protection');
    }
  }

  // Check for embedded video in Office docs
  if (content.includes('video/mp4') || content.includes('video/avi') ||
      content.includes('oleObject') && content.includes('video')) {
    flags.push('embedded_video');
  }

  return flags;
}

/**
 * Compute SHA-512 hash of a file. (Tessera v3.1 §6.4, §10.1)
 * Used for document registration and integrity verification.
 */
export function computeFileHash(filePath: string): string {
  const fileBuffer = fs.readFileSync(filePath);
  return createHash('sha512').update(fileBuffer).digest('hex');
}

/**
 * Compute SHA-512 hash from a buffer.
 */
export function computeBufferHash(buffer: Buffer): string {
  return createHash('sha512').update(buffer).digest('hex');
}

/**
 * Validate an uploaded file against Tessera's supported formats.
 * (Tessera v3.1 §6.1)
 *
 * Checks:
 *   1. File extension is recognized
 *   2. Declared MIME type is in supported list
 *   3. Magic bytes match declared MIME type (anti-spoofing)
 *   4. File is not empty or oversized
 *   5. Unsupported content detection (macros, JS, DRM, etc.)
 */
export async function validateFormat(
  filePath: string,
  declaredMimeType: string,
  originalFilename: string,
  maxSizeBytes: number = 500 * 1024 * 1024 // 500MB default
): Promise<FormatValidationResult> {
  const errors: string[] = [];
  const ext = path.extname(originalFilename).toLowerCase();

  // Read file
  let buffer: Buffer;
  let stat: fs.Stats;
  try {
    stat = fs.statSync(filePath);
    buffer = fs.readFileSync(filePath);
  } catch (err: any) {
    return {
      valid: false,
      mimeType: declaredMimeType,
      detectedMimeType: 'unknown',
      category: null,
      fileExtension: ext,
      sizeBytes: 0,
      unsupportedFlags: [],
      errors: [`File read error: ${err.message}`],
    };
  }

  // Size check
  if (stat.size === 0) {
    errors.push('File is empty');
  }
  if (stat.size > maxSizeBytes) {
    errors.push(`File exceeds maximum size of ${maxSizeBytes} bytes`);
  }

  // MIME type in supported list?
  const mimeEntry = SUPPORTED_MIME_TYPES[declaredMimeType];
  if (!mimeEntry) {
    errors.push(`Unsupported MIME type: ${declaredMimeType}`);
  }

  // Extension matches declared MIME type?
  if (mimeEntry && !mimeEntry.extensions.includes(ext)) {
    errors.push(
      `File extension ${ext} does not match declared type ${declaredMimeType} ` +
      `(expected: ${mimeEntry.extensions.join(', ')})`
    );
  }

  // Magic byte detection (skip for plain text and HTML — no reliable magic)
  let detectedMimeType = declaredMimeType;
  if (!['text/plain', 'text/html'].includes(declaredMimeType)) {
    const detected = detectMimeFromBytes(buffer);
    if (detected) {
      detectedMimeType = detected[0];
      if (!detected.includes(declaredMimeType)) {
        // ZIP-based formats all share the same magic bytes — allow any OOXML
        const bothOoxml = detected.some(d => d.includes('openxmlformats')) &&
                          declaredMimeType.includes('openxmlformats');
        const bothLegacy = detected.some(d => d.includes('ms-')) &&
                           (declaredMimeType.includes('msword') ||
                            declaredMimeType.includes('ms-excel') ||
                            declaredMimeType.includes('ms-powerpoint'));

        if (!bothOoxml && !bothLegacy) {
          errors.push(
            `MIME type mismatch: declared ${declaredMimeType} but ` +
            `file signature suggests ${detected.join(' or ')}`
          );
        }
      }
    } else if (buffer.length > 4) {
      // Unknown magic bytes — not necessarily invalid (some formats lack signatures)
      // Log but don't reject
    }
  }

  // Unsupported content detection
  const unsupportedFlags = detectUnsupportedContent(buffer, declaredMimeType);

  const valid = errors.length === 0;

  return {
    valid,
    mimeType: declaredMimeType,
    detectedMimeType,
    category: mimeEntry?.category || null,
    fileExtension: ext,
    sizeBytes: stat.size,
    unsupportedFlags,
    errors,
  };
}
