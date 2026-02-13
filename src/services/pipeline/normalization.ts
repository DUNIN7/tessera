// =============================================================================
// TESSERA — Document Normalization Service
//
// Converts uploaded documents to an internal intermediate format
// preserving structure, formatting, images, graphics, tables, and layout.
// (Tessera v3.1 §6.2)
//
// "Normalized representation hash recorded alongside original document
// hash, providing verifiable chain from original to canonical form."
//
// Phase 2 implementation: Produces a structured JSON intermediate
// representation. Full format-specific parsers (PDF extraction,
// Office document parsing, OCR for scanned documents) will be
// expanded iteratively. The interface and hash chain are production-ready.
// =============================================================================

import * as fs from 'fs';
import * as path from 'path';
import { createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { NormalizationResult, SUPPORTED_MIME_TYPES } from '../../types/pipeline';

/**
 * Internal intermediate document representation.
 * This is the canonical format Tessera works with after intake.
 * All markup, deconstruction, and reconstruction operate on this format.
 */
export interface IntermediateDocument {
  /** Tessera intermediate format version */
  formatVersion: '1.0';

  /** Unique ID for this normalized representation */
  id: string;

  /** Source document metadata */
  source: {
    originalHash: string;
    mimeType: string;
    filename: string;
  };

  /** Document structure — ordered array of content blocks */
  blocks: ContentBlock[];

  /** Document-level metadata extracted during normalization */
  metadata: {
    title?: string;
    author?: string;
    createdDate?: string;
    modifiedDate?: string;
    pageCount?: number;
    wordCount?: number;
    languages?: string[];
  };
}

/**
 * A content block in the intermediate representation.
 * Each block is independently addressable for markup and extraction.
 */
export interface ContentBlock {
  /** Unique block ID within the document */
  blockId: string;

  /** Block type */
  type: 'paragraph' | 'heading' | 'table' | 'image' | 'list' | 'page_break' | 'section_break';

  /** Page number this block appears on (1-indexed) */
  page: number;

  /** Sequential position within the document */
  position: number;

  /** Text content (for text-based blocks) */
  text?: string;

  /** Heading level (for heading blocks) */
  headingLevel?: number;

  /** Table data (for table blocks) — rows × columns */
  tableData?: string[][];

  /** Image reference (for image blocks) — path to extracted image */
  imageRef?: string;

  /** Style/formatting metadata (preserved for reconstruction) */
  style?: Record<string, string>;
}

// Storage directory for normalized documents
const NORMALIZED_DIR = process.env.TESSERA_NORMALIZED_DIR || '/app/data/normalized';

/**
 * Normalize a document into the intermediate representation.
 * (Tessera v3.1 §6.2)
 *
 * Phase 2: Implements text-based format normalization (plain text, HTML, RTF).
 * PDF, Office, and image formats produce structured placeholders with
 * metadata extraction. Full parsing requires format-specific libraries
 * added in later phases.
 *
 * The normalization hash is computed over the canonical JSON representation,
 * providing a verifiable chain from original to normalized form.
 */
export async function normalizeDocument(
  filePath: string,
  originalHash: string,
  mimeType: string,
  originalFilename: string
): Promise<NormalizationResult> {
  const errors: string[] = [];

  try {
    // Ensure output directory exists
    const docDir = path.join(NORMALIZED_DIR, uuidv4());
    fs.mkdirSync(docDir, { recursive: true });

    // Read file content
    const buffer = fs.readFileSync(filePath);
    const category = getCategoryForMime(mimeType);

    // Build intermediate representation based on format
    let blocks: ContentBlock[];
    let metadata: IntermediateDocument['metadata'] = {};

    switch (category) {
      case 'text':
        ({ blocks, metadata } = normalizeText(buffer));
        break;

      case 'html':
        ({ blocks, metadata } = normalizeHtml(buffer));
        break;

      case 'pdf':
      case 'word':
      case 'excel':
      case 'powerpoint':
      case 'rtf':
        // Phase 2: Structured placeholder with metadata.
        // Full parsing requires mammoth (Word), pdf-parse (PDF),
        // xlsx (Excel), pptx libraries — added in Phase 3+.
        ({ blocks, metadata } = createPlaceholderRepresentation(buffer, category, originalFilename));
        break;

      case 'image':
        ({ blocks, metadata } = normalizeImage(filePath, docDir, originalFilename));
        break;

      default:
        errors.push(`No normalizer for category: ${category}`);
        return { success: false, normalizedPath: null, normalizedHash: null, metadata: { hasImages: false, hasTables: false }, errors };
    }

    // Build the intermediate document
    const intermediate: IntermediateDocument = {
      formatVersion: '1.0',
      id: uuidv4(),
      source: { originalHash, mimeType, filename: originalFilename },
      blocks,
      metadata,
    };

    // Write canonical JSON
    const canonicalJson = JSON.stringify(intermediate, null, 2);
    const normalizedPath = path.join(docDir, 'normalized.json');
    fs.writeFileSync(normalizedPath, canonicalJson);

    // Compute hash of the normalized representation (§6.2)
    const normalizedHash = createHash('sha512').update(canonicalJson).digest('hex');

    return {
      success: true,
      normalizedPath,
      normalizedHash,
      metadata: {
        pageCount: metadata.pageCount,
        wordCount: metadata.wordCount,
        hasImages: blocks.some(b => b.type === 'image'),
        hasTables: blocks.some(b => b.type === 'table'),
        languages: metadata.languages,
      },
      errors,
    };
  } catch (err: any) {
    return {
      success: false,
      normalizedPath: null,
      normalizedHash: null,
      metadata: { hasImages: false, hasTables: false },
      errors: [`Normalization error: ${err.message}`],
    };
  }
}

// ── Format-Specific Normalizers ────────────────────────────────────────

function normalizeText(buffer: Buffer): {
  blocks: ContentBlock[];
  metadata: IntermediateDocument['metadata'];
} {
  const text = buffer.toString('utf-8');
  const paragraphs = text.split(/\n\n+/).filter(p => p.trim());

  const blocks: ContentBlock[] = paragraphs.map((para, i) => ({
    blockId: `blk_${String(i + 1).padStart(4, '0')}`,
    type: 'paragraph' as const,
    page: 1,
    position: i + 1,
    text: para.trim(),
  }));

  const wordCount = text.split(/\s+/).filter(w => w).length;

  return {
    blocks,
    metadata: { wordCount, pageCount: 1 },
  };
}

function normalizeHtml(buffer: Buffer): {
  blocks: ContentBlock[];
  metadata: IntermediateDocument['metadata'];
} {
  const html = buffer.toString('utf-8');

  // Basic HTML → blocks extraction.
  // Strip tags for text content, preserve structure markers.
  const blocks: ContentBlock[] = [];
  let position = 0;

  // Extract title
  const titleMatch = html.match(/<title[^>]*>(.*?)<\/title>/is);
  const title = titleMatch ? titleMatch[1].trim() : undefined;

  // Split on block-level elements
  const blockPattern = /<(h[1-6]|p|div|table|li|blockquote)[^>]*>(.*?)<\/\1>/gis;
  let match;

  while ((match = blockPattern.exec(html)) !== null) {
    position++;
    const tag = match[1].toLowerCase();
    const content = match[2].replace(/<[^>]+>/g, '').trim();

    if (!content) continue;

    if (tag.startsWith('h')) {
      blocks.push({
        blockId: `blk_${String(position).padStart(4, '0')}`,
        type: 'heading',
        page: 1,
        position,
        text: content,
        headingLevel: parseInt(tag[1]),
      });
    } else {
      blocks.push({
        blockId: `blk_${String(position).padStart(4, '0')}`,
        type: 'paragraph',
        page: 1,
        position,
        text: content,
      });
    }
  }

  // Fallback: if no block elements found, treat entire body as text
  if (blocks.length === 0) {
    const bodyMatch = html.match(/<body[^>]*>(.*?)<\/body>/is);
    const bodyText = (bodyMatch ? bodyMatch[1] : html)
      .replace(/<style[^>]*>.*?<\/style>/gis, '')
      .replace(/<script[^>]*>.*?<\/script>/gis, '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();

    if (bodyText) {
      blocks.push({
        blockId: 'blk_0001',
        type: 'paragraph',
        page: 1,
        position: 1,
        text: bodyText,
      });
    }
  }

  const wordCount = blocks.reduce((sum, b) => sum + (b.text?.split(/\s+/).length || 0), 0);

  return {
    blocks,
    metadata: { title, wordCount, pageCount: 1 },
  };
}

function normalizeImage(
  filePath: string,
  docDir: string,
  filename: string
): {
  blocks: ContentBlock[];
  metadata: IntermediateDocument['metadata'];
} {
  // Copy image to normalized directory
  const imageDest = path.join(docDir, 'image_001' + path.extname(filename));
  fs.copyFileSync(filePath, imageDest);

  return {
    blocks: [{
      blockId: 'blk_0001',
      type: 'image',
      page: 1,
      position: 1,
      imageRef: imageDest,
    }],
    metadata: { pageCount: 1 },
  };
}

function createPlaceholderRepresentation(
  buffer: Buffer,
  category: string,
  filename: string
): {
  blocks: ContentBlock[];
  metadata: IntermediateDocument['metadata'];
} {
  // Phase 2 placeholder: records that the document exists and its category.
  // Full parsing will extract actual content blocks in Phase 3+
  // when format-specific libraries are integrated.
  return {
    blocks: [{
      blockId: 'blk_0001',
      type: 'paragraph',
      page: 1,
      position: 1,
      text: `[Awaiting ${category} parser — document registered: ${filename}, ${buffer.length} bytes]`,
    }],
    metadata: {
      pageCount: undefined,
      wordCount: undefined,
    },
  };
}

// ── Helpers ────────────────────────────────────────────────────────────

function getCategoryForMime(mime: string): string {
  return SUPPORTED_MIME_TYPES[mime]?.category || 'unknown';
}
