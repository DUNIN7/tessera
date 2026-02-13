-- =============================================================================
-- TESSERA — Phase 3 Schema Additions: Markup Engine
--
-- Tables for markup sessions, operations (with undo/redo history),
-- AI suggestions, and the approval/review workflow.
-- (Tessera v3.1 §7, §8)
--
-- This file is applied AFTER the Phase 1 schema (01-schema.sql).
-- In Docker, mount as /docker-entrypoint-initdb.d/03-markup-schema.sql
-- =============================================================================

-- =============================================================================
-- ENUMERATED TYPES (Markup-specific)
-- =============================================================================

-- Markup session status.
CREATE TYPE markup_session_status AS ENUM (
  'active',       -- Redactor is actively marking up
  'paused',       -- Session saved, can be resumed
  'submitted',    -- Submitted for review
  'revision',     -- Sent back from reviewer for changes
  'approved',     -- Reviewer approved markup
  'abandoned'     -- Abandoned without submission
);

-- Markup operation types for undo/redo history. (Tessera v3.1 §7.2)
CREATE TYPE markup_operation_type AS ENUM (
  'assign',         -- Assign selection(s) to a content set
  'unassign',       -- Remove selection(s) from a content set
  'bulk_assign',    -- Bulk assign (pattern match, propagation)
  'bulk_unassign'   -- Bulk remove
);

-- What triggered a markup operation.
CREATE TYPE markup_operation_source AS ENUM (
  'manual',               -- Redactor directly selected and assigned
  'pattern',              -- Pattern-based redaction (§7.3 bullet 2)
  'propagation',          -- Auto-propagation of selected term (§7.3 bullet 3)
  'suggestion_accepted'   -- AI suggestion accepted by redactor (§7.3)
);

-- Content selection granularity. (Tessera v3.1 §7.2)
CREATE TYPE selection_granularity AS ENUM (
  'character',      -- Character-level selection
  'word',           -- Word-level selection
  'sentence',       -- Sentence-level selection
  'paragraph',      -- Paragraph-level selection
  'section',        -- Section-level selection
  'image',          -- Entire image as single unit (§7.2)
  'table',          -- Entire table (bulk selection)
  'page',           -- Entire page (bulk selection)
  'named_section'   -- Named section (bulk selection)
);

-- AI suggestion types. (Tessera v3.1 §7.3, §7.4, §13.1)
CREATE TYPE suggestion_type AS ENUM (
  'redaction',      -- Suggests content likely requiring redaction
  'pattern',        -- Pattern-based: all instances of pattern
  'propagation',    -- Auto-highlight all occurrences of term
  'template',       -- Reusable config for recurring doc types
  'personal_data',  -- GDPR erasure strategy (§13.1)
  'coded_content'   -- Ongoing coded content awareness (§7.4)
);

-- Suggestion resolution status.
CREATE TYPE suggestion_status AS ENUM (
  'pending',    -- Awaiting redactor decision
  'accepted',   -- Redactor accepted and applied
  'rejected',   -- Redactor explicitly rejected
  'dismissed'   -- Redactor dismissed without action
);

-- Review decision. (Tessera v3.1 §8.1)
CREATE TYPE review_decision AS ENUM (
  'approve',          -- Triggers deconstruction (§8.3)
  'reject',           -- Rejected with comments
  'request_changes',  -- Sent back to redactor
  'escalate'          -- Escalated per §8.2
);

-- Escalation level. (Tessera v3.1 §8.2)
CREATE TYPE escalation_level AS ENUM (
  'direct_resolution',       -- Redactor/reviewer resolve via comments
  'org_admin_arbitration',   -- Admin reviews, issues binding decision
  'cross_org_arbitration'    -- For trust group documents
);

-- =============================================================================
-- MARKUP SESSIONS
-- =============================================================================

-- Tracks the state of a redactor's markup work on a document.
-- (Tessera v3.1 §7)
--
-- "Markup proceeds one content set at a time." (§7.1)
-- "Previously marked content displayed in red as visual aid;
-- does not prevent multi-set assignment." (§7.1)
CREATE TABLE markup_sessions (
  id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Document being marked up. FK to documents table.
  document_id                 UUID NOT NULL REFERENCES documents(id),

  -- Organization (denormalized for tenant-scoped queries).
  organization_id             UUID NOT NULL REFERENCES organizations(id),

  -- Redactor performing the markup. Must hold 'redactor' role.
  redactor_id                 UUID NOT NULL REFERENCES users(id),

  -- Current session status.
  status                      markup_session_status NOT NULL DEFAULT 'active',

  -- Which content set is currently being marked up (§7.1).
  -- NULL when no set is active (session just created or between sets).
  -- Redactor works on one set at a time; switches via UI.
  active_content_set          VARCHAR(50),

  -- Total operations performed in this session (including undone ones).
  -- Used for sequence numbering.
  operation_count             INT NOT NULL DEFAULT 0,

  -- Current position in the undo/redo stack.
  -- Points to the last executed (non-undone) operation sequence number.
  -- Undo decrements this; redo increments it.
  undo_position               INT NOT NULL DEFAULT 0,

  -- Session-level notes from the redactor.
  notes                       TEXT,

  -- Whether this session builds on a previous version's markup.
  -- (Tessera v3.1 §14: "System assists by displaying previous markup
  -- in distinct color")
  previous_version_session_id UUID REFERENCES markup_sessions(id),

  created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_markup_sessions_doc ON markup_sessions(document_id);
CREATE INDEX idx_markup_sessions_org ON markup_sessions(organization_id);
CREATE INDEX idx_markup_sessions_redactor ON markup_sessions(redactor_id);
CREATE INDEX idx_markup_sessions_status ON markup_sessions(status);

-- =============================================================================
-- MARKUP OPERATIONS
-- =============================================================================

-- Individual markup operations forming the undo/redo history.
-- (Tessera v3.1 §7.2: "Undo/redo with full history within markup session")
--
-- Each operation is atomic: it assigns or unassigns one or more
-- content selections to/from a content set. Operations are sequentially
-- numbered within a session. Undo marks an operation as undone; redo
-- restores it. New operations after an undo truncate the redo stack
-- (all operations with sequence > undo_position are marked abandoned).
CREATE TABLE markup_operations (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Session this operation belongs to.
  session_id              UUID NOT NULL REFERENCES markup_sessions(id) ON DELETE CASCADE,

  -- Operation type.
  type                    markup_operation_type NOT NULL,

  -- Target content set identifier (e.g., "A", "B", "C").
  content_set_identifier  VARCHAR(50) NOT NULL,

  -- Sequential position within the session's operation history.
  -- Monotonically increasing. Used for undo/redo positioning.
  sequence_number         INT NOT NULL,

  -- Whether this operation has been undone.
  is_undone               BOOLEAN NOT NULL DEFAULT false,

  -- What triggered this operation.
  source                  markup_operation_source NOT NULL DEFAULT 'manual',

  -- If source is 'pattern', the pattern that was applied.
  -- (Tessera v3.1 §7.3: "redactor specifies patterns; system
  -- applies across entire document")
  pattern                 TEXT,

  -- If source is 'suggestion_accepted', the suggestion ID.
  suggestion_id           UUID,

  created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),

  UNIQUE(session_id, sequence_number)
);

CREATE INDEX idx_markup_ops_session ON markup_operations(session_id);
CREATE INDEX idx_markup_ops_sequence ON markup_operations(session_id, sequence_number);

-- =============================================================================
-- MARKUP SELECTIONS
-- =============================================================================

-- Content selections within markup operations.
-- Each operation can affect multiple selections (e.g., bulk assign).
-- Selections reference content blocks in the intermediate document
-- representation produced during normalization (§6.2).
CREATE TABLE markup_selections (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Operation this selection belongs to.
  operation_id      UUID NOT NULL REFERENCES markup_operations(id) ON DELETE CASCADE,

  -- Content block ID from the intermediate representation (normalization).
  block_id          VARCHAR(50) NOT NULL,

  -- Selection granularity. (Tessera v3.1 §7.2)
  granularity       selection_granularity NOT NULL,

  -- Start offset within the block's text content (character index).
  -- NULL for whole-block selections (image, table, page).
  start_offset      INT,

  -- End offset within the block's text content (character index, exclusive).
  -- NULL for whole-block selections.
  end_offset        INT,

  -- Snapshot of the selected text at the time of selection.
  -- Preserved for audit trail; not used for reconstruction.
  -- NULL for non-text selections (images).
  selected_text     TEXT,

  -- Page number where this selection appears (from the intermediate doc).
  page_number       INT NOT NULL DEFAULT 1
);

CREATE INDEX idx_markup_selections_op ON markup_selections(operation_id);
CREATE INDEX idx_markup_selections_block ON markup_selections(block_id);

-- =============================================================================
-- CONTENT SET ASSIGNMENTS (materialized state)
-- =============================================================================

-- Materialized view of current content-to-set assignments.
-- Derived from applying all non-undone operations in sequence.
-- Updated after each operation (assign, unassign, undo, redo).
--
-- This table represents the CURRENT STATE of the markup — what
-- content is assigned to what set right now. The operations table
-- is the HISTORY (for undo/redo). Both are needed.
--
-- Cross-set overlap (§5.3) is detected by querying this table
-- for selections that appear in multiple content sets.
CREATE TABLE content_set_assignments (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Session this assignment belongs to.
  session_id              UUID NOT NULL REFERENCES markup_sessions(id) ON DELETE CASCADE,

  -- Content set this content is assigned to.
  content_set_identifier  VARCHAR(50) NOT NULL,

  -- Content block from the intermediate representation.
  block_id                VARCHAR(50) NOT NULL,

  -- Character range within the block (NULL for whole-block).
  start_offset            INT,
  end_offset              INT,

  -- Snapshot of assigned text.
  selected_text           TEXT,

  -- Page number.
  page_number             INT NOT NULL DEFAULT 1,

  -- Operation that created this assignment (for provenance tracking).
  created_by_operation_id UUID REFERENCES markup_operations(id),

  created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_csa_session ON content_set_assignments(session_id);
CREATE INDEX idx_csa_set ON content_set_assignments(session_id, content_set_identifier);
CREATE INDEX idx_csa_block ON content_set_assignments(block_id);

-- Detect cross-set overlap: same block+range in multiple sets.
-- (Tessera v3.1 §5.3)
CREATE INDEX idx_csa_overlap ON content_set_assignments(
  session_id, block_id, start_offset, end_offset
);

-- =============================================================================
-- AI SUGGESTIONS
-- =============================================================================

-- AI-generated suggestions for redaction markup.
-- (Tessera v3.1 §7.3: "Advisory only; nothing applied without
-- explicit human approval. AI never generates, modifies, or
-- inserts content.")
--
-- Also covers ongoing coded content awareness alerts (§7.4):
-- "During markup, AI continues monitoring for coded content patterns
-- emerging in context. Alerts redactor if markup selections
-- inadvertently split coded content leaving encoded information
-- in the base document."
CREATE TABLE markup_suggestions (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Session this suggestion belongs to.
  session_id              UUID NOT NULL REFERENCES markup_sessions(id) ON DELETE CASCADE,

  -- Suggestion type. (Tessera v3.1 §7.3, §7.4, §13.1)
  type                    suggestion_type NOT NULL,

  -- Current status.
  status                  suggestion_status NOT NULL DEFAULT 'pending',

  -- Suggested content set to assign to.
  -- NULL for informational alerts (coded_content type).
  suggested_content_set   VARCHAR(50),

  -- Why the AI suggested this. Human-readable rationale.
  rationale               TEXT NOT NULL,

  -- Confidence score (0.0 - 1.0).
  confidence              NUMERIC(3,2) NOT NULL DEFAULT 0.5,

  -- For pattern suggestions: the detected pattern.
  pattern                 TEXT,

  -- For coded content alerts (§7.4): the specific concern.
  coded_content_alert     TEXT,

  -- JSONB array of content selections this suggestion applies to.
  -- Stored as JSON because suggestions may reference many selections
  -- and the structure matches ContentSelection interface.
  selections              JSONB NOT NULL DEFAULT '[]',

  -- When the redactor resolved this suggestion.
  resolved_at             TIMESTAMPTZ,

  -- Who resolved it (should be the session's redactor).
  resolved_by             UUID REFERENCES users(id),

  created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_suggestions_session ON markup_suggestions(session_id);
CREATE INDEX idx_suggestions_status ON markup_suggestions(status);
CREATE INDEX idx_suggestions_type ON markup_suggestions(type);

-- =============================================================================
-- REVIEWS
-- =============================================================================

-- Review records for the approval workflow.
-- (Tessera v3.1 §8.1, §8.2)
--
-- "Reviewer must have visibility into all content sets. If not,
-- system requires upgraded reviewer or multi-reviewer workflow
-- with full-coverage verification." (§8.1)
CREATE TABLE markup_reviews (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Markup session under review.
  session_id              UUID NOT NULL REFERENCES markup_sessions(id),

  -- Document being reviewed (denormalized).
  document_id             UUID NOT NULL REFERENCES documents(id),

  -- Organization (denormalized for tenant scoping).
  organization_id         UUID NOT NULL REFERENCES organizations(id),

  -- Reviewer making the decision. Must hold 'reviewer' role.
  reviewer_id             UUID NOT NULL REFERENCES users(id),

  -- Decision. (Tessera v3.1 §8.1)
  decision                review_decision NOT NULL,

  -- Reviewer's comments explaining the decision.
  comments                TEXT NOT NULL DEFAULT '',

  -- Whether the reviewer verified they have visibility into ALL
  -- content sets. (Tessera v3.1 §8.1: "Reviewer must have visibility
  -- into all content sets.")
  full_coverage_verified  BOOLEAN NOT NULL DEFAULT false,

  -- If escalated (§8.2): which escalation level.
  escalation_level        escalation_level,

  -- If escalated to org admin: the admin's binding decision.
  arbitration_decision    TEXT,
  arbitration_by          UUID REFERENCES users(id),
  arbitration_at          TIMESTAMPTZ,

  -- FORAY transaction ID for this review event.
  foray_tx_id             VARCHAR(255),

  created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_reviews_session ON markup_reviews(session_id);
CREATE INDEX idx_reviews_doc ON markup_reviews(document_id);
CREATE INDEX idx_reviews_org ON markup_reviews(organization_id);
CREATE INDEX idx_reviews_reviewer ON markup_reviews(reviewer_id);
