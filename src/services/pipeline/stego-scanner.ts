// =============================================================================
// TESSERA — Coded Content & Steganographic Detection Service
//
// "This is a mandatory intake gate. No document proceeds to markup
// until coded content scanning is complete." (Tessera v3.1 §6.3)
//
// "AI-assisted detection is mandatory; human-only review is insufficient."
//
// Detects:
//   1. Unicode anomalies — homoglyphs, zero-width characters, directional
//      overrides, non-standard whitespace
//   2. Encoding patterns — acrostics, first-letter patterns, statistical
//      anomalies, unusual repetition
//   3. Image steganography — LSB analysis, DCT coefficient analysis,
//      palette manipulation, statistical deviation
//   4. Metadata payloads — hidden content in metadata fields, custom XML,
//      embedded objects, comment fields
//   5. Structural anomalies — invisible text layers in PDFs, hidden
//      rows/columns in spreadsheets, off-canvas content, font-size-zero
//
// Phase 2: Implements categories 1, 2, 4, and partial 5 for text-based
// formats. Image steganography (category 3) and deep structural analysis
// require specialized libraries and the self-hosted AI model (§13.2),
// integrated in Phase 6 (Hardening).
// =============================================================================

import * as fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import {
  ScanFinding,
  ScanSeverity,
  StegoScanResult,
} from '../../types/pipeline';

const SCANNER_VERSION = 'tessera-stego-scanner-0.2.0';

// ── Unicode Anomaly Detection ──────────────────────────────────────────

/**
 * Known homoglyph mappings — characters that look identical to ASCII
 * but are from different Unicode blocks. (Tessera v3.1 §6.3)
 *
 * Common substitutions used to embed covert channels:
 *   Cyrillic 'а' (U+0430) ↔ Latin 'a' (U+0061)
 *   Cyrillic 'е' (U+0435) ↔ Latin 'e' (U+0065)
 *   Cyrillic 'о' (U+043E) ↔ Latin 'o' (U+006F)
 *   Greek 'ο' (U+03BF) ↔ Latin 'o' (U+006F)
 */
const HOMOGLYPH_RANGES = [
  { name: 'Cyrillic',                  start: 0x0400, end: 0x04FF },
  { name: 'Greek',                     start: 0x0370, end: 0x03FF },
  { name: 'Fullwidth Latin',           start: 0xFF01, end: 0xFF5E },
  { name: 'Mathematical Alphanumeric', start: 0x1D400, end: 0x1D7FF },
  { name: 'Enclosed Alphanumerics',    start: 0x2460, end: 0x24FF },
  { name: 'Letterlike Symbols',        start: 0x2100, end: 0x214F },
];

/**
 * Zero-width and invisible characters that can encode hidden data.
 */
const INVISIBLE_CHARS: Record<number, string> = {
  0x200B: 'Zero-Width Space',
  0x200C: 'Zero-Width Non-Joiner',
  0x200D: 'Zero-Width Joiner',
  0xFEFF: 'Zero-Width No-Break Space (BOM)',
  0x2060: 'Word Joiner',
  0x2061: 'Function Application',
  0x2062: 'Invisible Times',
  0x2063: 'Invisible Separator',
  0x2064: 'Invisible Plus',
  0x180E: 'Mongolian Vowel Separator',
  0x00AD: 'Soft Hyphen',
};

/**
 * Directional override characters that can manipulate text display.
 */
const DIRECTIONAL_OVERRIDES: Record<number, string> = {
  0x202A: 'Left-to-Right Embedding',
  0x202B: 'Right-to-Left Embedding',
  0x202C: 'Pop Directional Formatting',
  0x202D: 'Left-to-Right Override',
  0x202E: 'Right-to-Left Override',
  0x2066: 'Left-to-Right Isolate',
  0x2067: 'Right-to-Left Isolate',
  0x2068: 'First Strong Isolate',
  0x2069: 'Pop Directional Isolate',
};

function detectUnicodeAnomalies(text: string): ScanFinding[] {
  const findings: ScanFinding[] = [];

  // Scan for homoglyphs in primarily Latin text
  const latinRatio = (text.match(/[a-zA-Z]/g)?.length || 0) / Math.max(text.length, 1);
  if (latinRatio > 0.3) {
    // Document is primarily Latin — non-Latin look-alikes are suspicious
    for (const range of HOMOGLYPH_RANGES) {
      const matches: { char: string; code: string; position: number }[] = [];
      for (let i = 0; i < text.length; i++) {
        const code = text.codePointAt(i) || 0;
        if (code >= range.start && code <= range.end) {
          matches.push({
            char: text[i],
            code: `U+${code.toString(16).toUpperCase().padStart(4, '0')}`,
            position: i,
          });
        }
      }

      if (matches.length > 0) {
        findings.push({
          id: uuidv4(),
          category: 'unicode_anomaly',
          severity: matches.length > 10 ? 'high' : 'medium',
          description: `${matches.length} ${range.name} character(s) found in primarily Latin text. Possible homoglyph substitution.`,
          location: `Character positions: ${matches.slice(0, 5).map(m => m.position).join(', ')}${matches.length > 5 ? '...' : ''}`,
          indicators: matches.slice(0, 10).map(m => `${m.char} (${m.code})`),
          confidence: matches.length > 5 ? 0.85 : 0.6,
        });
      }
    }
  }

  // Scan for invisible / zero-width characters
  const invisibleFound: { code: number; name: string; count: number }[] = [];
  for (const [codeStr, name] of Object.entries(INVISIBLE_CHARS)) {
    const code = parseInt(codeStr);
    const char = String.fromCodePoint(code);
    const count = (text.split(char).length - 1);
    if (count > 0) {
      invisibleFound.push({ code, name, count });
    }
  }

  if (invisibleFound.length > 0) {
    const totalCount = invisibleFound.reduce((s, f) => s + f.count, 0);
    findings.push({
      id: uuidv4(),
      category: 'unicode_anomaly',
      severity: totalCount > 20 ? 'critical' : totalCount > 5 ? 'high' : 'medium',
      description: `${totalCount} invisible/zero-width character(s) detected. These can encode hidden binary data.`,
      location: 'Throughout document text content',
      indicators: invisibleFound.map(f => `${f.name}: ${f.count} occurrence(s)`),
      confidence: 0.9,
    });
  }

  // Scan for directional overrides
  const directionalFound: string[] = [];
  for (const [codeStr, name] of Object.entries(DIRECTIONAL_OVERRIDES)) {
    const code = parseInt(codeStr);
    if (text.includes(String.fromCodePoint(code))) {
      directionalFound.push(name);
    }
  }

  if (directionalFound.length > 0) {
    findings.push({
      id: uuidv4(),
      category: 'unicode_anomaly',
      severity: 'high',
      description: 'Unicode directional override characters detected. Can manipulate displayed text order.',
      location: 'Throughout document text content',
      indicators: directionalFound,
      confidence: 0.95,
    });
  }

  return findings;
}

// ── Encoding Pattern Detection ─────────────────────────────────────────

function detectEncodingPatterns(text: string): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const lines = text.split('\n').filter(l => l.trim());

  if (lines.length < 5) return findings;

  // First-letter acrostic detection
  const firstLetters = lines
    .map(l => l.trim()[0])
    .filter(c => c && /[a-zA-Z]/.test(c))
    .join('');

  if (firstLetters.length >= 5) {
    // Check if first letters form recognizable patterns
    // Statistical test: is the distribution of first letters significantly
    // different from expected English first-letter frequency?
    const uniqueRatio = new Set(firstLetters.toLowerCase().split('')).size / firstLetters.length;

    // Very low unique ratio in a long sequence suggests intentional patterning
    if (uniqueRatio < 0.3 && firstLetters.length > 10) {
      findings.push({
        id: uuidv4(),
        category: 'encoding_pattern',
        severity: 'medium',
        description: 'First-letter pattern detected across consecutive lines. Possible acrostic encoding.',
        location: `First ${Math.min(lines.length, 20)} lines`,
        indicators: [`First letters: "${firstLetters.slice(0, 30)}${firstLetters.length > 30 ? '...' : ''}"`, `Unique ratio: ${uniqueRatio.toFixed(2)}`],
        confidence: 0.5,
      });
    }

    // Check for dictionary words in first letters
    const commonWords = ['help', 'send', 'secret', 'data', 'code', 'hide', 'attack', 'bomb', 'kill', 'hack'];
    const firstLetterLower = firstLetters.toLowerCase();
    for (const word of commonWords) {
      if (firstLetterLower.includes(word)) {
        findings.push({
          id: uuidv4(),
          category: 'encoding_pattern',
          severity: 'high',
          description: `Suspicious word "${word}" detected in first-letter acrostic pattern.`,
          location: 'Line-initial characters',
          indicators: [`Acrostic sequence contains: "${word}"`],
          confidence: 0.75,
        });
      }
    }
  }

  // Unusual character repetition detection
  // Look for statistically anomalous character frequency distributions
  const charFreq: Record<string, number> = {};
  for (const ch of text.toLowerCase()) {
    if (/[a-z]/.test(ch)) {
      charFreq[ch] = (charFreq[ch] || 0) + 1;
    }
  }

  const totalLetters = Object.values(charFreq).reduce((s, c) => s + c, 0);
  if (totalLetters > 200) {
    // Expected English letter frequencies (approximate)
    const expectedFreq: Record<string, number> = {
      e: 0.127, t: 0.091, a: 0.082, o: 0.075, i: 0.070,
      n: 0.067, s: 0.063, h: 0.061, r: 0.060, d: 0.043,
      l: 0.040, c: 0.028, u: 0.028, m: 0.024, w: 0.024,
      f: 0.022, g: 0.020, y: 0.020, p: 0.019, b: 0.015,
      v: 0.010, k: 0.008, j: 0.002, x: 0.002, q: 0.001, z: 0.001,
    };

    // Chi-squared test for deviation from expected distribution
    let chiSquared = 0;
    for (const [letter, expected] of Object.entries(expectedFreq)) {
      const observed = (charFreq[letter] || 0) / totalLetters;
      chiSquared += Math.pow(observed - expected, 2) / expected;
    }

    // High chi-squared suggests non-natural text
    if (chiSquared > 0.05) {
      findings.push({
        id: uuidv4(),
        category: 'encoding_pattern',
        severity: chiSquared > 0.15 ? 'high' : 'medium',
        description: 'Character frequency distribution deviates significantly from natural language. Possible encoded content.',
        location: 'Overall document text',
        indicators: [`Chi-squared deviation: ${chiSquared.toFixed(4)}`, `Total letters analyzed: ${totalLetters}`],
        confidence: Math.min(0.4 + chiSquared * 2, 0.85),
      });
    }
  }

  return findings;
}

// ── Metadata Payload Detection ─────────────────────────────────────────

function detectMetadataPayloads(
  buffer: Buffer,
  mimeType: string
): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const content = buffer.toString('utf-8', 0, Math.min(buffer.length, 500000));

  // PDF-specific metadata checks
  if (mimeType === 'application/pdf') {
    // Check for hidden JavaScript in PDF metadata
    if (/\/AA\s/.test(content) || /\/OpenAction/.test(content)) {
      findings.push({
        id: uuidv4(),
        category: 'metadata_payload',
        severity: 'high',
        description: 'PDF contains automatic action triggers (AA/OpenAction). May execute hidden operations.',
        location: 'PDF document catalog',
        indicators: ['Automatic action detected in PDF structure'],
        confidence: 0.85,
      });
    }

    // Check for embedded files in PDF
    if (/\/EmbeddedFile/.test(content)) {
      findings.push({
        id: uuidv4(),
        category: 'metadata_payload',
        severity: 'medium',
        description: 'PDF contains embedded file attachments. Hidden data may be present in attachments.',
        location: 'PDF embedded files',
        indicators: ['EmbeddedFile stream detected'],
        confidence: 0.7,
      });
    }
  }

  // Office document metadata checks (OOXML — ZIP-based)
  if (mimeType.includes('openxmlformats')) {
    // Check for custom XML parts
    if (content.includes('customXml') || content.includes('CustomXML')) {
      findings.push({
        id: uuidv4(),
        category: 'metadata_payload',
        severity: 'medium',
        description: 'Office document contains custom XML parts. May contain hidden structured data.',
        location: 'Document custom XML',
        indicators: ['customXml part detected in OOXML package'],
        confidence: 0.6,
      });
    }

    // Check for comment fields with substantial content
    if (content.includes('w:comment') || content.includes('comments.xml')) {
      findings.push({
        id: uuidv4(),
        category: 'metadata_payload',
        severity: 'low',
        description: 'Office document contains comments. Review for hidden information in comment fields.',
        location: 'Document comments',
        indicators: ['Comment elements detected'],
        confidence: 0.4,
      });
    }
  }

  // HTML metadata checks
  if (mimeType === 'text/html') {
    // Hidden form fields
    if (/type\s*=\s*["']hidden["']/i.test(content)) {
      findings.push({
        id: uuidv4(),
        category: 'metadata_payload',
        severity: 'medium',
        description: 'HTML contains hidden form fields. May carry hidden data.',
        location: 'HTML form elements',
        indicators: ['Hidden input fields detected'],
        confidence: 0.6,
      });
    }

    // data: URIs that could embed arbitrary content
    const dataUriCount = (content.match(/data:[^;]+;base64/g) || []).length;
    if (dataUriCount > 0) {
      findings.push({
        id: uuidv4(),
        category: 'metadata_payload',
        severity: dataUriCount > 5 ? 'high' : 'medium',
        description: `HTML contains ${dataUriCount} base64 data URI(s). Arbitrary data may be embedded.`,
        location: 'HTML data URIs',
        indicators: [`${dataUriCount} data:...;base64 URI(s) found`],
        confidence: 0.7,
      });
    }
  }

  return findings;
}

// ── Structural Anomaly Detection ───────────────────────────────────────

function detectStructuralAnomalies(
  buffer: Buffer,
  mimeType: string
): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const content = buffer.toString('utf-8', 0, Math.min(buffer.length, 500000));

  // PDF invisible text layers
  if (mimeType === 'application/pdf') {
    // Text rendering mode 3 = invisible text (common in OCR PDFs, but
    // also used for hiding data)
    if (/Tr\s+3/.test(content) || /\/Rendering\s+3/.test(content)) {
      findings.push({
        id: uuidv4(),
        category: 'structural_anomaly',
        severity: 'medium',
        description: 'PDF contains invisible text rendering (mode 3). Common in OCR but may hide content.',
        location: 'PDF text rendering operators',
        indicators: ['Text render mode 3 (invisible) detected'],
        confidence: 0.5,
      });
    }

    // Font size zero
    if (/\/FontSize\s+0\b/.test(content) || /\bTf\s+0\s/.test(content)) {
      findings.push({
        id: uuidv4(),
        category: 'structural_anomaly',
        severity: 'high',
        description: 'PDF contains zero-size font text. Invisible to viewers but carries data.',
        location: 'PDF font definitions',
        indicators: ['Font size 0 detected'],
        confidence: 0.85,
      });
    }
  }

  // HTML off-screen / hidden content
  if (mimeType === 'text/html') {
    // CSS hiding: display:none, visibility:hidden, position:absolute with
    // large negative offsets, font-size:0
    const hidePatterns = [
      { pattern: /display\s*:\s*none/gi, name: 'display:none' },
      { pattern: /visibility\s*:\s*hidden/gi, name: 'visibility:hidden' },
      { pattern: /font-size\s*:\s*0/gi, name: 'font-size:0' },
      { pattern: /position\s*:\s*absolute[^}]*?left\s*:\s*-\d{4,}/gi, name: 'off-screen positioning' },
      { pattern: /overflow\s*:\s*hidden[^}]*?height\s*:\s*0/gi, name: 'zero-height overflow hidden' },
    ];

    for (const { pattern, name } of hidePatterns) {
      const matches = content.match(pattern);
      if (matches && matches.length > 0) {
        findings.push({
          id: uuidv4(),
          category: 'structural_anomaly',
          severity: 'medium',
          description: `HTML contains ${name} elements (${matches.length} instance(s)). Content may be visually hidden.`,
          location: 'HTML/CSS structure',
          indicators: [`${matches.length} instance(s) of ${name}`],
          confidence: 0.55,
        });
      }
    }
  }

  // Spreadsheet hidden rows/columns (OOXML)
  if (mimeType.includes('spreadsheetml')) {
    if (content.includes('hidden="1"') || content.includes('hidden="true"')) {
      findings.push({
        id: uuidv4(),
        category: 'structural_anomaly',
        severity: 'high',
        description: 'Spreadsheet contains hidden rows, columns, or sheets. Data may be concealed.',
        location: 'Spreadsheet structure',
        indicators: ['Hidden attribute detected in sheet XML'],
        confidence: 0.8,
      });
    }
  }

  return findings;
}

// ── Main Scanner ───────────────────────────────────────────────────────

/**
 * Run the complete coded content / steganographic scan.
 * (Tessera v3.1 §6.3: "This is a mandatory intake gate.")
 *
 * Phase 2 implements text-based analysis. Image steganography
 * (LSB analysis, DCT coefficient analysis) deferred to Phase 6
 * with self-hosted AI model integration (§13.2).
 */
export async function scanForCodedContent(
  filePath: string,
  mimeType: string
): Promise<StegoScanResult> {
  const buffer = fs.readFileSync(filePath);
  const text = buffer.toString('utf-8', 0, Math.min(buffer.length, 1000000));

  const allFindings: ScanFinding[] = [];

  // 1. Unicode anomalies (§6.3 bullet 1)
  allFindings.push(...detectUnicodeAnomalies(text));

  // 2. Encoding patterns (§6.3 bullet 2)
  allFindings.push(...detectEncodingPatterns(text));

  // 3. Image steganography (§6.3 bullet 3)
  // Phase 2: Stub — full LSB/DCT analysis requires image processing libraries
  // and the self-hosted AI model (§13.2).
  if (mimeType.startsWith('image/')) {
    allFindings.push({
      id: uuidv4(),
      category: 'image_steganography',
      severity: 'info',
      description: 'Image steganography analysis pending. Full LSB/DCT analysis available in Phase 6.',
      location: 'Image content',
      indicators: ['Deep image analysis not yet available'],
      confidence: 0.0,
    });
  }

  // 4. Metadata payloads (§6.3 bullet 4)
  allFindings.push(...detectMetadataPayloads(buffer, mimeType));

  // 5. Structural anomalies (§6.3 bullet 5)
  allFindings.push(...detectStructuralAnomalies(buffer, mimeType));

  // Compute overall severity
  const severityOrder: ScanSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const overallSeverity = allFindings.length > 0
    ? allFindings.reduce((worst, f) => {
        return severityOrder.indexOf(f.severity) < severityOrder.indexOf(worst)
          ? f.severity
          : worst;
      }, 'info' as ScanSeverity)
    : 'info';

  return {
    scanComplete: true,
    scannedAt: new Date().toISOString(),
    overallSeverity,
    findings: allFindings,
    scannerVersion: SCANNER_VERSION,
  };
}

