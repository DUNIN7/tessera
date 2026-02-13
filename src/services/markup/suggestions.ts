// =============================================================================
// TESSERA — AI Suggestion Service
//
// "Advisory only; nothing applied without explicit human approval.
// AI never generates, modifies, or inserts content." (§7.3, §13.1)
//
// Capabilities (§13.1):
//   - Redaction suggestions: names, dates, addresses, classified terms
//   - Pattern matching: all instances of specified patterns
//   - Propagation: auto-highlight all occurrences of selected term
//   - Template profiles: reusable configs for recurring document types
//   - Personal data flagging: GDPR erasure strategy (§13.1)
//   - Coded content monitoring: ongoing awareness during markup (§7.4)
//
// Phase 3: Implements rule-based suggestion generation (regex patterns,
// keyword lists). Full AI model integration (§13.2: "AI model must be
// self-hosted within the system's trust boundary") deferred to Phase 6.
// =============================================================================

import { pool } from '../../db/pool';
import { v4 as uuidv4 } from 'uuid';
import { ContentSelection, SuggestionType, SuggestionStatus } from '../../types/markup';

// ── Pattern Libraries (rule-based, Phase 3) ────────────────────────────

/** Common patterns for automatic suggestion generation. */
const REDACTION_PATTERNS: Array<{
  name: string;
  pattern: RegExp;
  category: string;
  confidence: number;
}> = [
  // Personal identifiers
  { name: 'email_address',   pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,       category: 'personal_data', confidence: 0.9 },
  { name: 'phone_us',        pattern: /\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b/g, category: 'personal_data', confidence: 0.7 },
  { name: 'ssn',             pattern: /\b\d{3}-\d{2}-\d{4}\b/g,                                        category: 'personal_data', confidence: 0.95 },
  { name: 'date',            pattern: /\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b/g,                       category: 'temporal',      confidence: 0.6 },
  { name: 'iso_date',        pattern: /\b\d{4}-\d{2}-\d{2}\b/g,                                        category: 'temporal',      confidence: 0.7 },

  // Financial
  { name: 'currency_usd',    pattern: /\$[\d,]+\.?\d{0,2}\b/g,                                         category: 'financial',     confidence: 0.8 },
  { name: 'currency_other',  pattern: /(?:€|£|¥)[\d,]+\.?\d{0,2}\b/g,                                  category: 'financial',     confidence: 0.8 },
  { name: 'account_number',  pattern: /\b\d{8,17}\b/g,                                                 category: 'financial',     confidence: 0.4 },

  // Addresses (simplified — full NER is Phase 6)
  { name: 'zip_code',        pattern: /\b\d{5}(?:-\d{4})?\b/g,                                         category: 'address',       confidence: 0.5 },
  { name: 'po_box',          pattern: /\bP\.?O\.?\s*Box\s+\d+\b/gi,                                    category: 'address',       confidence: 0.85 },

  // Classification markers
  { name: 'classified',      pattern: /\b(?:CONFIDENTIAL|SECRET|TOP SECRET|CLASSIFIED|RESTRICTED|SENSITIVE)\b/g, category: 'classification', confidence: 0.9 },
  { name: 'fouo',            pattern: /\b(?:FOUO|FOR OFFICIAL USE ONLY|NOFORN|ORCON)\b/g,               category: 'classification', confidence: 0.95 },
];

/**
 * Generate redaction suggestions for a document's content blocks.
 * (§7.3: "suggests content likely requiring redaction —
 * names, dates, addresses, classified terms, financial figures")
 *
 * Phase 3: Rule-based pattern matching. Phase 6 adds self-hosted
 * NER/NLP model for entity recognition and context-aware suggestions.
 */
export async function generateSuggestions(params: {
  sessionId: string;
  documentBlocks: Array<{ blockId: string; text: string; page: number }>;
}): Promise<{ suggestionCount: number }> {
  let count = 0;

  for (const block of params.documentBlocks) {
    if (!block.text) continue;

    for (const patternDef of REDACTION_PATTERNS) {
      // Reset regex state (global flag)
      patternDef.pattern.lastIndex = 0;
      let match;

      while ((match = patternDef.pattern.exec(block.text)) !== null) {
        const selection: ContentSelection = {
          selectionId: uuidv4(),
          blockId: block.blockId,
          granularity: 'word',
          startOffset: match.index,
          endOffset: match.index + match[0].length,
          selectedText: match[0],
          page: block.page,
        };

        await pool.query(
          `INSERT INTO markup_suggestions
             (id, session_id, type, status, suggested_content_set,
              rationale, confidence, pattern, selections)
           VALUES ($1, $2, 'redaction', 'pending', NULL, $3, $4, $5, $6)`,
          [
            uuidv4(),
            params.sessionId,
            `${patternDef.name} detected (${patternDef.category}): "${match[0]}"`,
            patternDef.confidence,
            patternDef.name,
            JSON.stringify([selection]),
          ]
        );

        count++;
      }
    }
  }

  return { suggestionCount: count };
}

/**
 * Generate coded content awareness alerts during markup. (§7.4)
 * "AI continues monitoring for coded content patterns emerging in context.
 *  Alerts redactor if markup selections inadvertently split coded content
 *  leaving encoded information in the base document."
 *
 * Phase 3: Checks for basic positional encoding risks in current assignments.
 * Full context-aware analysis requires self-hosted AI model (Phase 6).
 */
export async function checkCodedContentRisk(params: {
  sessionId: string;
  documentBlocks: Array<{ blockId: string; text: string; page: number }>;
}): Promise<{ alertCount: number }> {
  let alertCount = 0;

  // Get current assignments for this session
  const assignments = await pool.query(
    `SELECT block_id, content_set_identifier, start_offset, end_offset
     FROM content_set_assignments
     WHERE session_id = $1
     ORDER BY block_id, start_offset`,
    [params.sessionId]
  );

  // Check for patterns where partial selection of structured content
  // could leave positional encoding in the base document.
  // Example: if every other row of a table is redacted, the remaining
  // rows' positions could encode information.
  const assignedByBlock: Record<string, Array<{ start: number | null; end: number | null; set: string }>> = {};
  for (const row of assignments.rows) {
    if (!assignedByBlock[row.block_id]) assignedByBlock[row.block_id] = [];
    assignedByBlock[row.block_id].push({
      start: row.start_offset,
      end: row.end_offset,
      set: row.content_set_identifier,
    });
  }

  for (const block of params.documentBlocks) {
    const blockAssignments = assignedByBlock[block.blockId] || [];
    if (blockAssignments.length === 0) continue;

    // Check for alternating pattern (every other selection in same set)
    // This is a simplified heuristic; full analysis requires AI model.
    if (blockAssignments.length >= 4) {
      const sets = blockAssignments.map(a => a.set);
      const alternating = sets.every((s, i) =>
        i === 0 || s === sets[i % 2 === 0 ? 0 : 1]
      );

      if (alternating && new Set(sets).size > 1) {
        await pool.query(
          `INSERT INTO markup_suggestions
             (id, session_id, type, status, rationale, confidence, coded_content_alert, selections)
           VALUES ($1, $2, 'coded_content', 'pending', $3, $4, $5, $6)`,
          [
            uuidv4(),
            params.sessionId,
            `Alternating assignment pattern detected in block ${block.blockId}. Remaining content positions may encode information.`,
            0.5,
            'Alternating content set assignments create positional encoding risk (§7.4)',
            JSON.stringify([{
              selectionId: uuidv4(),
              blockId: block.blockId,
              granularity: 'paragraph',
              startOffset: null,
              endOffset: null,
              page: block.page,
            }]),
          ]
        );
        alertCount++;
      }
    }
  }

  return { alertCount };
}

/**
 * Resolve a suggestion: accept, reject, or dismiss. (§7.3)
 * "Nothing applied without explicit human approval."
 */
export async function resolveSuggestion(params: {
  suggestionId: string;
  sessionId: string;
  status: SuggestionStatus;
  resolvedBy: string;
}): Promise<void> {
  if (params.status === 'pending') {
    throw new Error('Cannot resolve a suggestion back to pending');
  }

  const result = await pool.query(
    `UPDATE markup_suggestions
     SET status = $1, resolved_at = now(), resolved_by = $2
     WHERE id = $3 AND session_id = $4 AND status = 'pending'
     RETURNING id`,
    [params.status, params.resolvedBy, params.suggestionId, params.sessionId]
  );

  if (result.rows.length === 0) {
    throw new Error('Suggestion not found or already resolved');
  }
}

/**
 * List suggestions for a session with optional filtering.
 */
export async function listSuggestions(params: {
  sessionId: string;
  status?: SuggestionStatus;
  type?: SuggestionType;
  limit?: number;
  offset?: number;
}) {
  const conditions = ['session_id = $1'];
  const values: any[] = [params.sessionId];
  let idx = 2;

  if (params.status) {
    conditions.push(`status = $${idx++}`);
    values.push(params.status);
  }
  if (params.type) {
    conditions.push(`type = $${idx++}`);
    values.push(params.type);
  }

  const limit = params.limit || 50;
  const offset = params.offset || 0;

  const result = await pool.query(
    `SELECT id, type, status, suggested_content_set, rationale,
            confidence, pattern, coded_content_alert, selections,
            created_at, resolved_at
     FROM markup_suggestions
     WHERE ${conditions.join(' AND ')}
     ORDER BY confidence DESC, created_at DESC
     LIMIT ${limit} OFFSET ${offset}`,
    values
  );

  return result.rows;
}
