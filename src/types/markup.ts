// =============================================================================
// TESSERA — Markup Engine Types
//
// Types for the markup phase: sessions, content selection, content set
// assignment, AI suggestions, overlap detection, and approval workflow.
// (Tessera v3.1 §7, §8)
// =============================================================================

// ── Selection Types ────────────────────────────────────────────────────

/**
 * Granularity of content selection. (Tessera v3.1 §7.2)
 * "Text selection at character, word, sentence, paragraph, and section levels.
 *  Image/graphic selection: entire image as single unit.
 *  Bulk selection: entire tables, pages, or named sections."
 */
export type SelectionGranularity =
  | 'character'
  | 'word'
  | 'sentence'
  | 'paragraph'
  | 'section'
  | 'image'       // Entire image as single unit (§7.2)
  | 'table'       // Entire table (bulk selection)
  | 'page'        // Entire page (bulk selection)
  | 'named_section'; // Named section (bulk selection)

/**
 * A content selection within the intermediate document.
 * References specific content blocks and ranges within them.
 */
export interface ContentSelection {
  /** Unique selection ID */
  selectionId: string;

  /** Content block ID from the intermediate representation */
  blockId: string;

  /** Selection granularity */
  granularity: SelectionGranularity;

  /** Start offset within the block's text content (character index).
   *  NULL for whole-block selections (image, table, page). */
  startOffset: number | null;

  /** End offset within the block's text content (character index, exclusive).
   *  NULL for whole-block selections. */
  endOffset: number | null;

  /** The selected text (for text-based selections). Read-only snapshot. */
  selectedText?: string;

  /** Page number where this selection appears */
  page: number;
}

// ── Markup Operations ──────────────────────────────────────────────────

/**
 * Types of markup operations that form the undo/redo history.
 * (Tessera v3.1 §7.2: "Undo/redo with full history within markup session")
 */
export type MarkupOperationType =
  | 'assign'        // Assign selection to a content set
  | 'unassign'      // Remove selection from a content set
  | 'bulk_assign'   // Bulk assign (pattern match, propagation)
  | 'bulk_unassign'; // Bulk remove

/**
 * A single markup operation. Stored in the operation history for
 * undo/redo support. Each operation is atomic and reversible.
 */
export interface MarkupOperation {
  /** Unique operation ID */
  operationId: string;

  /** Session this operation belongs to */
  sessionId: string;

  /** Operation type */
  type: MarkupOperationType;

  /** Target content set identifier (e.g., "A", "B", "C") */
  contentSetIdentifier: string;

  /** Content selections affected by this operation */
  selections: ContentSelection[];

  /** Sequential position in the session's operation history */
  sequenceNumber: number;

  /** Whether this operation has been undone */
  isUndone: boolean;

  /** What triggered this operation */
  source: 'manual' | 'pattern' | 'propagation' | 'suggestion_accepted';

  /** If source is 'pattern', the pattern that was applied */
  pattern?: string;

  /** If source is 'suggestion_accepted', the suggestion ID */
  suggestionId?: string;

  /** Timestamp */
  createdAt: string;
}

// ── Markup Sessions ────────────────────────────────────────────────────

/**
 * Markup session status.
 */
export type MarkupSessionStatus =
  | 'active'         // Redactor is actively marking up
  | 'paused'         // Session saved, can be resumed
  | 'submitted'      // Submitted for review
  | 'revision'       // Sent back from reviewer for changes
  | 'approved'       // Reviewer approved
  | 'abandoned';     // Abandoned without submission

/**
 * Markup session. (Tessera v3.1 §7)
 * Tracks the state of a redactor's work on a document.
 * "Markup proceeds one content set at a time." (§7.1)
 */
export interface MarkupSession {
  id: string;
  documentId: string;
  organizationId: string;
  redactorId: string;
  status: MarkupSessionStatus;

  /** Which content set is currently being marked up (§7.1) */
  activeContentSetIdentifier: string | null;

  /** Total operations in this session */
  operationCount: number;

  /** Current position in undo/redo stack */
  undoPosition: number;

  /** Session-level notes from the redactor */
  notes: string | null;

  createdAt: string;
  updatedAt: string;
}

// ── AI Suggestions ─────────────────────────────────────────────────────

/**
 * AI suggestion types. (Tessera v3.1 §7.3)
 * "Advisory only; nothing applied without explicit human approval."
 */
export type SuggestionType =
  | 'redaction'      // Suggests content likely requiring redaction (§7.3 bullet 1)
  | 'pattern'        // Pattern-based: all instances of specified pattern (§7.3 bullet 2)
  | 'propagation'    // Auto-highlight all occurrences of selected term (§7.3 bullet 3)
  | 'template'       // Reusable configuration for recurring doc types (§7.3 bullet 4)
  | 'personal_data'  // Identifies personal data for GDPR erasure strategy (§13.1)
  | 'coded_content'; // Ongoing coded content awareness during markup (§7.4)

/**
 * AI suggestion status.
 */
export type SuggestionStatus =
  | 'pending'    // Awaiting redactor decision
  | 'accepted'   // Redactor accepted and applied
  | 'rejected'   // Redactor explicitly rejected
  | 'dismissed'; // Redactor dismissed without action

/**
 * An AI-generated suggestion. (Tessera v3.1 §7.3)
 * "AI never generates, modifies, or inserts content." (§13.1)
 */
export interface MarkupSuggestion {
  id: string;
  sessionId: string;
  type: SuggestionType;
  status: SuggestionStatus;

  /** Suggested content set to assign to (null for informational alerts) */
  suggestedContentSet: string | null;

  /** Content selections the suggestion applies to */
  selections: ContentSelection[];

  /** Why the AI suggested this */
  rationale: string;

  /** Confidence score (0.0 - 1.0) */
  confidence: number;

  /** For pattern suggestions: the detected pattern */
  pattern?: string;

  /** For coded content alerts (§7.4): the concern */
  codedContentAlert?: string;

  createdAt: string;
  resolvedAt?: string;
}

// ── Overlap Detection ──────────────────────────────────────────────────

/**
 * Cross-set overlap report entry. (Tessera v3.1 §5.3)
 * "During markup, warnings displayed when content assigned to multiple sets,
 *  showing resulting access level visibility."
 */
export interface OverlapEntry {
  /** The content selection that appears in multiple sets */
  selection: ContentSelection;

  /** Content sets this selection is assigned to */
  contentSets: string[];

  /** Access levels that would see this content (any one set grants visibility) */
  visibleAtLevels: string[];
}

/**
 * Complete overlap report for reviewer verification. (Tessera v3.1 §5.3)
 * "Approval workflow includes cross-set overlap report for reviewer verification."
 */
export interface OverlapReport {
  documentId: string;
  sessionId: string;

  /** Total selections with cross-set overlap */
  overlapCount: number;

  /** Individual overlap entries */
  entries: OverlapEntry[];

  /** Generated timestamp */
  generatedAt: string;
}

// ── Approval Workflow ──────────────────────────────────────────────────

/**
 * Review decision. (Tessera v3.1 §8.1)
 * "Approve (triggers deconstruction), reject with comments,
 *  or request changes."
 */
export type ReviewDecision =
  | 'approve'          // Triggers deconstruction pipeline (§8.3)
  | 'reject'           // Rejected with comments
  | 'request_changes'  // Sent back to redactor for revision
  | 'escalate';        // Escalated per §8.2

/**
 * Escalation level. (Tessera v3.1 §8.2)
 */
export type EscalationLevel =
  | 'direct_resolution'          // Redactor/reviewer resolve via comments
  | 'org_admin_arbitration'      // Admin reviews and issues binding decision
  | 'cross_org_arbitration';     // For trust group documents

/**
 * A review record. Tracks reviewer actions on submitted markup.
 */
export interface ReviewRecord {
  id: string;
  sessionId: string;
  documentId: string;
  reviewerId: string;
  decision: ReviewDecision;

  /** Reviewer's comments */
  comments: string;

  /** If escalated, the escalation level */
  escalationLevel?: EscalationLevel;

  /** If escalated to org admin, the admin's binding decision */
  arbitrationDecision?: string;
  arbitrationBy?: string;

  /** Whether the reviewer had visibility into all content sets (§8.1) */
  fullCoverageVerified: boolean;

  createdAt: string;
}
