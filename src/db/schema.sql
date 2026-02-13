-- =============================================================================
-- TESSERA — Database Schema
-- Secure Document Redaction & Access Control System
--
-- Owner/Licensor: Marvin Percival — marvinp@dunin7.com
-- Repository:     github.com/DUNIN7/tessera
-- License:        Business Source License 1.1 (BSL 1.1)
--
-- Architecture:   Parallel Tessera + Ova tiered deployment
--                 (Tessera_Ova_Parallel_Architecture_Evaluation §8)
--
-- This schema implements the Tier 1 (conventional server-mediated) 
-- authorization model. The authorization_provider abstraction in the
-- security_profiles table enables Tier 2/3 (Ova composed-proof) 
-- backends without schema changes.
--
-- Roles follow the eight-role model from the Parallel Architecture
-- Evaluation §9, with structural separation between content-layer
-- and access-control-layer roles.
-- =============================================================================

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- ENUMERATED TYPES
-- =============================================================================

-- Eight roles across two structural layers.
-- Content-layer roles (Tessera §4): System Admin, Org Admin, Redactor,
--   Reviewer, Viewer, Auditor.
-- Access-control-layer roles (Parallel Eval §9): ACL Author, Asset Provisioner.
--
-- The Org Admin role is flagged for future split into Package Composer + 
-- Group Administrator per Parallel Eval §9 and SBX Enigma precedent.
-- For now it spans both sub-roles; the layer_guard middleware prevents
-- it from crossing into content operations it shouldn't touch.
CREATE TYPE user_role AS ENUM (
  -- Content layer roles (Tessera v3.1 §4)
  'system_admin',       -- Platform config, org provisioning. NO document/key access.
  'org_admin',          -- Access level CRUD, user mgmt, dispute arbitration.
                        -- NO unilateral reconstruction. Future split target.
  'redactor',           -- Document markup. Access only during active sessions.
  'reviewer',           -- Markup approval. Must see ALL content sets under review.
  'viewer',             -- Reconstructed document access per authorized level.
  'auditor',            -- Read-only audit trails. NO decrypted content access.
  
  -- Access-control-layer roles (Parallel Architecture Eval §9)
  'acl_author',         -- Creates authorization rules (ACL Eggs in Ova terms).
                        -- Defines conditions, permission types, group references.
                        -- Cannot see document content, manage groups, or provision assets.
  'asset_provisioner'   -- Creates asset protection objects during deconstruction.
                        -- Handles key references. Cannot modify ACLs or groups.
                        -- Plaintext keys destroyed after egg/object creation.
);

-- Role layer assignment. Enforced by layer_guard middleware.
-- Content-layer roles CANNOT invoke access-control-layer operations.
-- Access-control-layer roles CANNOT invoke content-layer operations.
-- This is structural, not policy. (Parallel Eval §9: "compromise of any
-- content role reveals nothing about authorization, and vice versa.")
CREATE TYPE role_layer AS ENUM (
  'content',            -- Tessera application operations
  'access_control'      -- Authorization graph operations (Tier 1: RBAC; Tier 2/3: Ova)
);

-- Authorization tier selection per organization.
-- Parallel Architecture Evaluation §8: tiered deployment model.
CREATE TYPE authorization_tier AS ENUM (
  'tier_1',   -- Conventional server-mediated RBAC. Kaspa for audit only (FORAY).
  'tier_2',   -- Ova composed proofs with cached fallback during outages.
  'tier_3'    -- Ova composed proofs, hard dependency. No reconstruction without
              -- on-chain verification. Government/defense/intelligence.
);

-- Storage separation tiers. (Tessera v3.1 §10.3)
CREATE TYPE storage_tier AS ENUM (
  'tier_1',   -- Separate logical partitions, same data center.
              -- Corporate, low-sensitivity.
  'tier_2',   -- Separate data centers, different locations/teams.
              -- Healthcare, legal, high-sensitivity corporate.
  'tier_3'    -- Separate secure facilities, different jurisdictions/operators.
              -- Government, military, intelligence.
);

-- Document lifecycle status. (Tessera v3.1 §3.1)
CREATE TYPE document_status AS ENUM (
  'intake',             -- Uploaded, pending validation and stego scan
  'intake_flagged',     -- Stego/coded content scan flagged anomalies
  'intake_cleared',     -- Scan complete, cleared to proceed
  'markup',             -- Active markup in progress
  'markup_submitted',   -- Markup submitted for review
  'review',             -- Under reviewer examination
  'review_escalated',   -- Escalated per §8.2 escalation path
  'approved',           -- Markup approved, awaiting deconstruction
  'deconstructing',     -- Deconstruction in progress
  'active',             -- Deconstructed and available for reconstruction
  'destroying',         -- Destruction in progress
  'destroyed'           -- All content and keys destroyed; audit record persists
);

-- Audit event categories mapped to FORAY components.
-- (Tessera v3.1 §11.1, FORAY v4.1 4A model)
CREATE TYPE audit_category AS ENUM (
  'arrangement',        -- Document registration, access levels, trust agreements,
                        -- security profiles, IdP approvals
  'accrual',            -- Integrity computations, markup sessions, content set
                        -- hashes, steganographic scan findings
  'anticipation',       -- Expected events: reconstructions, expirations,
                        -- scheduled key rotations
  'action'              -- Executed events: reconstructions, exports, approvals,
                        -- escalations, incidents
);

-- =============================================================================
-- ORGANIZATIONS
-- =============================================================================

-- Multi-tenant organization. (Tessera v3.1 §3.3)
-- Each org has fully isolated document stores, access levels, encryption
-- keys, and audit trails. Tenant isolation enforced at infrastructure level.
CREATE TABLE organizations (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- Display name of the organization.
  name            VARCHAR(255) NOT NULL,
  
  -- URL-safe unique identifier for API routing and tenant scoping.
  slug            VARCHAR(100) NOT NULL UNIQUE,
  
  -- Whether this organization is currently active.
  -- Deactivated orgs retain data for audit but block new operations.
  is_active       BOOLEAN NOT NULL DEFAULT true,
  
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =============================================================================
-- SECURITY PROFILES
-- =============================================================================

-- Per-organization security configuration. (Tessera v3.1 §10.6)
-- This is where the authorization provider abstraction lives.
-- The authorization_tier field determines which IAuthorizationProvider
-- implementation the system uses for this organization:
--   tier_1 → ConventionalAuthProvider (server-mediated RBAC)
--   tier_2 → OvaAuthProvider with cached fallback (future)
--   tier_3 → OvaAuthProvider with hard dependency (future)
--
-- Parallel Architecture Evaluation §8: "The Tessera application defines
-- a clean interface boundary (an authorization provider abstraction)
-- that supports either a conventional access control backend or the
-- Ova composed-proof backend."
CREATE TABLE security_profiles (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- Organization this profile belongs to. One profile per org.
  organization_id         UUID NOT NULL UNIQUE REFERENCES organizations(id),
  
  -- Authorization tier. Determines which IAuthorizationProvider implementation
  -- handles authorization decisions for this organization.
  -- (Parallel Architecture Evaluation §8)
  auth_tier               authorization_tier NOT NULL DEFAULT 'tier_1',
  
  -- Physical storage separation requirement. (Tessera v3.1 §10.3)
  -- tier_1: same DC, separate partitions. tier_2: separate DCs.
  -- tier_3: separate facilities, jurisdictions, operators.
  storage_tier            storage_tier NOT NULL DEFAULT 'tier_1',
  
  -- Shamir's Secret Sharing threshold for key splitting.
  -- (Tessera v3.1 §10.2) M shares required out of N total.
  -- Only enforced in Tier 1. In Tier 2/3, Ova composed proofs replace
  -- Shamir's with structural M-of-N via ACL threshold conditions.
  key_split_m             INT NOT NULL DEFAULT 2,   -- minimum shares needed
  key_split_n             INT NOT NULL DEFAULT 3,   -- total shares distributed
  
  -- Whether document export is permitted, and at which access levels.
  -- (Tessera v3.1 §9.3, §10.6)
  export_permitted        BOOLEAN NOT NULL DEFAULT false,
  
  -- Whether invisible watermarks are applied to in-app viewing
  -- (always applied to exports). (Tessera v3.1 §10.5)
  watermark_in_app        BOOLEAN NOT NULL DEFAULT false,
  
  -- Session inactivity timeout in seconds. (Tessera v3.1 §10.4)
  -- Default 900s (15 min). No persistent sessions or "remember me".
  session_timeout_seconds INT NOT NULL DEFAULT 900,
  
  -- Key rotation interval in days. (Tessera v3.1 §10.2)
  -- 0 = manual rotation only.
  key_rotation_days       INT NOT NULL DEFAULT 90,
  
  -- Minimum data retention period in days before destruction is
  -- permitted. (Tessera v3.1 §12.1) Regulatory floor may extend this.
  min_retention_days      INT NOT NULL DEFAULT 365,
  
  -- Whether this org participates in any cross-organizational trust
  -- groups. (Tessera v3.1 §3.3) Trust group details in separate table.
  trust_groups_enabled    BOOLEAN NOT NULL DEFAULT false,
  
  -- JSON configuration for incident response notification.
  -- (Tessera v3.1 §10.7) Webhook URLs, email addresses, escalation.
  incident_config         JSONB NOT NULL DEFAULT '{}',
  
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  
  CONSTRAINT valid_key_split CHECK (key_split_m > 0 AND key_split_m <= key_split_n),
  CONSTRAINT valid_timeout CHECK (session_timeout_seconds >= 60),
  CONSTRAINT valid_retention CHECK (min_retention_days >= 0)
);

-- =============================================================================
-- USERS
-- =============================================================================

-- User accounts. (Tessera v3.1 §4, §10.4)
-- Users belong to exactly one organization for data isolation.
-- MFA is mandatory for all roles (§10.4).
-- Hardware security tokens (FIDO2/WebAuthn) required for redactor,
-- reviewer, all admin, and access-control-layer roles.
CREATE TABLE users (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- Organization this user belongs to. Enforces tenant isolation.
  organization_id   UUID NOT NULL REFERENCES organizations(id),
  
  -- Unique email address. Used as login identifier.
  email             VARCHAR(255) NOT NULL UNIQUE,
  
  -- bcrypt-hashed password. (Tessera v3.1 §10.1: Argon2id preferred
  -- for production; bcrypt acceptable for dev phase.)
  password_hash     VARCHAR(255) NOT NULL,
  
  -- Display name for UI and audit trail attribution.
  display_name      VARCHAR(255) NOT NULL,
  
  -- Whether MFA has been enrolled. (Tessera v3.1 §10.4)
  -- Login is blocked until MFA is configured.
  mfa_enrolled      BOOLEAN NOT NULL DEFAULT false,
  
  -- Whether a hardware security token (FIDO2/WebAuthn) is registered.
  -- Required for: redactor, reviewer, org_admin, system_admin,
  -- acl_author, asset_provisioner. (Tessera v3.1 §10.4)
  hardware_token_registered BOOLEAN NOT NULL DEFAULT false,
  
  is_active         BOOLEAN NOT NULL DEFAULT true,
  
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_users_org ON users(organization_id);
CREATE INDEX idx_users_email ON users(email);

-- =============================================================================
-- USER ROLE ASSIGNMENTS
-- =============================================================================

-- Maps users to roles with layer metadata. (Tessera v3.1 §4, Parallel Eval §9)
-- A user may hold multiple roles within their organization.
-- The layer column enables the layer_guard middleware to enforce structural
-- separation without joining back to role definitions at runtime.
--
-- Critical constraint: No combination of roles assigned to a single user
-- should enable unilateral document reconstruction. This is validated
-- at assignment time, not just checked at query time.
CREATE TABLE user_roles (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role        user_role NOT NULL,
  
  -- Which structural layer this role assignment operates in.
  -- Derived from the role at insertion time; stored for query efficiency.
  -- content: Tessera application operations
  -- access_control: authorization graph operations
  layer       role_layer NOT NULL,
  
  -- Optional: scope this role to a specific document or project.
  -- NULL = organization-wide. Used for per-document redactor assignments.
  scope_document_id UUID, -- FK added after documents table exists
  
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  
  UNIQUE(user_id, role)
);

CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_user_roles_layer ON user_roles(layer);

-- =============================================================================
-- ROLE-LAYER MAPPING REFERENCE
-- =============================================================================

-- Static reference table documenting which roles belong to which layer.
-- Used by application code to derive the layer column on user_roles insert.
-- (Parallel Architecture Evaluation §9)
CREATE TABLE role_layer_map (
  role        user_role PRIMARY KEY,
  layer       role_layer NOT NULL,
  description TEXT NOT NULL,
  
  -- What this role structurally CANNOT do.
  -- From Tessera v3.1 §4 and Parallel Eval §9 role table.
  cannot      TEXT NOT NULL
);

INSERT INTO role_layer_map (role, layer, description, cannot) VALUES
  ('system_admin',      'content',        'Platform config, org provisioning, security policy enforcement.',
    'Access document content or encryption keys. (Tessera §4)'),
  ('org_admin',         'content',        'Access level CRUD, user management, dispute arbitration. Future split into Package Composer + Group Admin.',
    'Unilateral reconstruction. Should not compose Packages AND administer Groups for same document. (Parallel Eval §9)'),
  ('redactor',          'content',        'Document markup for redaction at each content set.',
    'See Ova object graph, know who is authorized, access any egg. (Parallel Eval §9)'),
  ('reviewer',          'content',        'Reviews and approves redaction markup before deconstruction.',
    'See Ova object graph, modify authorization, access any egg. (Parallel Eval §9)'),
  ('viewer',            'content',        'Accesses reconstructed documents per authorized access level.',
    'See content beyond authorized level. Identity hidden from system via ZK in Tier 2/3. (Parallel Eval §9)'),
  ('auditor',           'content',        'Reviews audit trails, performs blockchain verification.',
    'Access document content, modify authorization, interact with Ova eggs. (Parallel Eval §9)'),
  ('acl_author',        'access_control', 'Creates authorization rules: conditions, permission types, group references.',
    'See document content, manage group membership, compose packages, provision assets. (Parallel Eval §9)'),
  ('asset_provisioner', 'access_control', 'Creates asset protection objects during deconstruction. Handles key refs.',
    'See document content post-deployment, modify ACLs or packages, manage groups. (Parallel Eval §9)')
;

-- =============================================================================
-- DOCUMENTS
-- =============================================================================

-- Document records. (Tessera v3.1 §6)
-- Documents belong to an organization. Content is stored separately
-- in content_sets after deconstruction; this table holds metadata.
CREATE TABLE documents (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- Organization owning this document. Tenant isolation boundary.
  organization_id       UUID NOT NULL REFERENCES organizations(id),
  
  -- Human-readable title.
  title                 VARCHAR(500) NOT NULL,
  
  -- Original filename at upload.
  original_filename     VARCHAR(500) NOT NULL,
  
  -- MIME type of the original upload. (Tessera v3.1 §6.1)
  -- Validated against supported formats at intake.
  mime_type             VARCHAR(100) NOT NULL,
  
  -- Size in bytes of the original upload.
  original_size_bytes   BIGINT NOT NULL,
  
  -- SHA-512 hash of the original uploaded file. (Tessera v3.1 §6.4)
  -- Committed to blockchain via FORAY Arrangement at intake.
  original_hash         VARCHAR(128) NOT NULL,
  
  -- SHA-512 hash of the normalized intermediate representation.
  -- (Tessera v3.1 §6.2) Provides verifiable chain from original
  -- to canonical form.
  normalized_hash       VARCHAR(128),
  
  -- Current lifecycle status. (Tessera v3.1 §3.1)
  status                document_status NOT NULL DEFAULT 'intake',
  
  -- FORAY transaction ID for the intake registration.
  -- (Tessera v3.1 §6.4, §11.1) Links to the Arrangement recording
  -- intake hashes, org, access level definitions, scan clearance.
  foray_intake_tx_id    VARCHAR(255),
  
  -- Result of mandatory coded content / steganographic scan.
  -- (Tessera v3.1 §6.3) NULL until scan completes.
  -- JSON: { severity, findings[], disposition, admin_decision }
  stego_scan_result     JSONB,
  
  -- Path to the normalized intermediate representation in internal storage.
  -- NULL until normalization completes.
  normalized_path       VARCHAR(1000),
  
  -- Document version chain. (Tessera v3.1 §14)
  -- NULL for first version; references predecessor for subsequent versions.
  -- Previous versions and content sets remain intact.
  previous_version_id   UUID REFERENCES documents(id),
  version_number        INT NOT NULL DEFAULT 1,
  
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_documents_org ON documents(organization_id);
CREATE INDEX idx_documents_status ON documents(status);
CREATE INDEX idx_documents_version_chain ON documents(previous_version_id);

-- Add FK for user_roles scope after documents table exists
ALTER TABLE user_roles 
  ADD CONSTRAINT fk_scope_document 
  FOREIGN KEY (scope_document_id) REFERENCES documents(id);

-- =============================================================================
-- CONTENT SETS
-- =============================================================================

-- Content sets produced during deconstruction. (Tessera v3.1 §5.1, §8.3)
-- Each content set is a separately encrypted data package containing
-- extracted content with positional markers. In Tier 2/3, each maps to
-- an Asset Egg on the Kaspa blockDAG.
CREATE TABLE content_sets (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- Document this set was extracted from.
  document_id       UUID NOT NULL REFERENCES documents(id),
  
  -- Organization (denormalized for efficient tenant-scoped queries).
  organization_id   UUID NOT NULL REFERENCES organizations(id),
  
  -- Identifier used in access level definitions (e.g., "A", "B", "C").
  -- (Tessera v3.1 §5.1)
  set_identifier    VARCHAR(50) NOT NULL,
  
  -- Human-readable label (e.g., "Operational", "Financial").
  label             VARCHAR(255) NOT NULL,
  
  -- SHA-512 hash of the encrypted content set. (Tessera v3.1 §8.3)
  -- Committed to blockchain via FORAY Accrual at deconstruction.
  encrypted_hash    VARCHAR(128),
  
  -- SHA-512 hash of the plaintext content set before encryption.
  -- Used for reconstruction integrity verification. (Tessera v3.1 §9.2)
  plaintext_hash    VARCHAR(128),
  
  -- Storage location reference. In Tier 1, a path or object store key.
  -- In Tier 2/3, this field is NULL — the location lives in the Asset
  -- Egg payload on the blockDAG, not in this database.
  storage_ref       VARCHAR(1000),
  
  -- Ova Asset Egg address on the Kaspa blockDAG.
  -- NULL in Tier 1 (no Ova). Populated in Tier 2/3 after egg deployment.
  -- (Tessera-on-Ova Architecture §3.2)
  ova_asset_egg_addr VARCHAR(255),
  
  -- FORAY transaction ID for the hash commitment.
  foray_hash_tx_id  VARCHAR(255),
  
  -- Whether this set has been destroyed (GDPR right-to-erasure).
  -- (Tessera v3.1 §12.3) Destroyed sets retain this metadata row
  -- for audit, but content and keys are gone.
  is_destroyed      BOOLEAN NOT NULL DEFAULT false,
  destroyed_at      TIMESTAMPTZ,
  
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  
  UNIQUE(document_id, set_identifier)
);

CREATE INDEX idx_content_sets_doc ON content_sets(document_id);
CREATE INDEX idx_content_sets_org ON content_sets(organization_id);

-- =============================================================================
-- ACCESS LEVELS
-- =============================================================================

-- Access level definitions. (Tessera v3.1 §5.1, §5.2)
-- Access levels are NOT hierarchical. Each is an arbitrary combination
-- of content sets. In Tier 2/3, each maps to a Package Egg defining
-- authorization rule combinations. (Parallel Eval §3: "No hierarchy
-- is implied or enforced — just different combinations.")
CREATE TABLE access_levels (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- Organization this level belongs to. Tenant isolation.
  organization_id   UUID NOT NULL REFERENCES organizations(id),
  
  -- Unique name within the organization (e.g., "Full Access", "Operational").
  name              VARCHAR(255) NOT NULL,
  
  description       TEXT,
  
  -- Whether document export is permitted at this level.
  -- Constrained by security_profile.export_permitted at the org level.
  -- (Tessera v3.1 §5.2)
  export_permitted  BOOLEAN NOT NULL DEFAULT false,
  
  -- Optional time-bound expiration. (Tessera v3.1 §5.4)
  -- NULL = no expiration. In Tier 2/3, time bounds are encoded as
  -- ACL Egg verification conditions; this field is the Tier 1 equivalent.
  expires_at        TIMESTAMPTZ,
  
  -- Whether this access level is currently active.
  -- Deactivated levels retained for audit. (Tessera v3.1 §5.2)
  is_active         BOOLEAN NOT NULL DEFAULT true,
  
  -- Ova Package Egg address. NULL in Tier 1.
  -- (Parallel Eval §3, Tessera-on-Ova §3.2)
  ova_package_egg_addr VARCHAR(255),
  
  -- FORAY transaction ID recording creation/modification.
  foray_tx_id       VARCHAR(255),
  
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  
  UNIQUE(organization_id, name)
);

CREATE INDEX idx_access_levels_org ON access_levels(organization_id);

-- =============================================================================
-- ACCESS LEVEL ↔ CONTENT SET MAPPING
-- =============================================================================

-- Defines which content sets are included in each access level.
-- (Tessera v3.1 §5.1) This is the core of the non-hierarchical model.
-- A content set may appear in multiple access levels (overlap).
-- In Tier 2/3, this mapping is encoded in Manifest Egg payloads;
-- this table is the Tier 1 equivalent and serves as the source of
-- truth during Ova egg deployment for Tier 2/3.
CREATE TABLE access_level_content_sets (
  access_level_id   UUID NOT NULL REFERENCES access_levels(id) ON DELETE CASCADE,
  content_set_id    UUID NOT NULL REFERENCES content_sets(id) ON DELETE CASCADE,
  
  PRIMARY KEY (access_level_id, content_set_id)
);

-- =============================================================================
-- USER ACCESS GRANTS
-- =============================================================================

-- Maps viewers to access levels for specific documents.
-- (Tessera v3.1 §5.4) In Tier 1, this is the authorization decision table.
-- In Tier 2/3, this is replaced by Ova composed-proof verification —
-- the grant exists in the credential bundle, not in this table.
-- The IAuthorizationProvider abstraction hides this difference.
CREATE TABLE user_access_grants (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  user_id           UUID NOT NULL REFERENCES users(id),
  document_id       UUID NOT NULL REFERENCES documents(id),
  access_level_id   UUID NOT NULL REFERENCES access_levels(id),
  
  -- Who granted this access.
  granted_by        UUID NOT NULL REFERENCES users(id),
  
  -- Optional time-bound expiration. (Tessera v3.1 §5.4)
  -- NULL = no expiration. Expired grants behave as no-access.
  expires_at        TIMESTAMPTZ,
  
  -- Whether this grant has been explicitly revoked.
  is_revoked        BOOLEAN NOT NULL DEFAULT false,
  revoked_at        TIMESTAMPTZ,
  revoked_by        UUID REFERENCES users(id),
  
  -- FORAY transaction ID for grant event.
  foray_grant_tx_id VARCHAR(255),
  
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  
  UNIQUE(user_id, document_id, access_level_id)
);

CREATE INDEX idx_grants_user ON user_access_grants(user_id);
CREATE INDEX idx_grants_document ON user_access_grants(document_id);

-- =============================================================================
-- TRUST GROUPS
-- =============================================================================

-- Cross-organizational trust groups. (Tessera v3.1 §3.3)
-- Organizations may form trust groups for cross-org document sharing
-- with per-organization security profiles.
CREATE TABLE trust_groups (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name            VARCHAR(255) NOT NULL,
  description     TEXT,
  
  -- Designated arbitration authority for disputes.
  -- (Tessera v3.1 §8.2 step 3)
  arbitration_authority TEXT,
  
  is_active       BOOLEAN NOT NULL DEFAULT true,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE trust_group_members (
  trust_group_id    UUID NOT NULL REFERENCES trust_groups(id),
  organization_id   UUID NOT NULL REFERENCES organizations(id),
  
  -- When this org joined the trust group.
  joined_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  
  PRIMARY KEY (trust_group_id, organization_id)
);

-- =============================================================================
-- AUDIT TRAIL
-- =============================================================================

-- Append-only audit log. (Tessera v3.1 §11)
-- Every auditable event is recorded here AND committed to the Kaspa
-- blockchain via FORAY Protocol. The local record enables fast queries;
-- the blockchain record provides tamper-evident external anchoring.
--
-- This table is INSERT-ONLY. No UPDATE or DELETE operations are
-- permitted. The application enforces this; a database trigger
-- provides defense-in-depth.
CREATE TABLE audit_trail (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- Timestamp of the event. Server-generated, not client-supplied.
  event_time        TIMESTAMPTZ NOT NULL DEFAULT now(),
  
  -- FORAY 4A component category. (Tessera v3.1 §11.1)
  -- arrangement: registrations, config changes
  -- accrual: integrity computations, markup sessions
  -- anticipation: expected future events
  -- action: executed events
  category          audit_category NOT NULL,
  
  -- Machine-readable event type for filtering and aggregation.
  -- Examples: 'document.intake', 'markup.submit', 'reconstruction.success',
  -- 'access_level.create', 'user.login', 'key.rotate'
  event_type        VARCHAR(100) NOT NULL,
  
  -- Human-readable description of what happened.
  description       TEXT NOT NULL,
  
  -- Organization scope. NULL for system-level events.
  organization_id   UUID REFERENCES organizations(id),
  
  -- User who performed the action. NULL for system-generated events.
  actor_id          UUID REFERENCES users(id),
  
  -- Role the actor was operating under when the event occurred.
  actor_role        user_role,
  
  -- Which structural layer the event belongs to.
  -- Enables auditors to filter content vs. access-control events.
  actor_layer       role_layer,
  
  -- Target entity. Polymorphic reference via type + ID.
  target_type       VARCHAR(50),    -- 'document', 'content_set', 'access_level', 'user', etc.
  target_id         UUID,
  
  -- Additional structured event data. Schema varies by event_type.
  -- Never contains plaintext document content or decrypted keys.
  metadata          JSONB NOT NULL DEFAULT '{}',
  
  -- SHA-512 hash of the event data for integrity verification.
  -- Included in the FORAY transaction for blockchain anchoring.
  event_hash        VARCHAR(128) NOT NULL,
  
  -- FORAY Protocol transaction ID after blockchain commitment.
  -- NULL if not yet committed (queued for batch commitment, or
  -- FORAY/Kaspa temporarily unavailable per §11.4 fallback).
  foray_tx_id       VARCHAR(255),
  
  -- Kaspa transaction ID from FORAY anchoring.
  kaspa_tx_id       VARCHAR(255),
  
  -- Whether this event has been committed to blockchain.
  is_anchored       BOOLEAN NOT NULL DEFAULT false,
  anchored_at       TIMESTAMPTZ
);

-- Audit trail indexes for common query patterns.
CREATE INDEX idx_audit_time ON audit_trail(event_time);
CREATE INDEX idx_audit_org ON audit_trail(organization_id);
CREATE INDEX idx_audit_actor ON audit_trail(actor_id);
CREATE INDEX idx_audit_type ON audit_trail(event_type);
CREATE INDEX idx_audit_target ON audit_trail(target_type, target_id);
CREATE INDEX idx_audit_category ON audit_trail(category);
CREATE INDEX idx_audit_unanchored ON audit_trail(is_anchored) WHERE is_anchored = false;

-- =============================================================================
-- AUDIT TRAIL IMMUTABILITY TRIGGER
-- =============================================================================

-- Defense-in-depth: prevent UPDATE and DELETE on audit_trail at the DB level.
-- The application layer also enforces this, but a compromised application
-- cannot bypass a database trigger.
CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Audit trail records are immutable. UPDATE and DELETE are prohibited.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_trail_no_update
  BEFORE UPDATE ON audit_trail
  FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE TRIGGER audit_trail_no_delete
  BEFORE DELETE ON audit_trail
  FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- =============================================================================
-- SESSIONS
-- =============================================================================

-- Active sessions. (Tessera v3.1 §10.4)
-- Short-lived, no persistent sessions, no "remember me".
-- Inactivity timeout per security profile (default 15 min).
CREATE TABLE sessions (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           UUID NOT NULL REFERENCES users(id),
  
  -- JWT token ID (jti claim) for this session.
  token_id          VARCHAR(255) NOT NULL UNIQUE,
  
  -- When the session was created (login time).
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  
  -- Last activity timestamp. Updated on every authenticated request.
  -- Session expires when now() - last_activity > org timeout.
  last_activity     TIMESTAMPTZ NOT NULL DEFAULT now(),
  
  -- When this session was explicitly terminated (logout or timeout).
  terminated_at     TIMESTAMPTZ,
  
  -- IP address at session creation (for audit, not for auth decisions).
  ip_address        INET,
  
  -- User agent string at session creation (for audit).
  user_agent        TEXT
);

CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_token ON sessions(token_id);
CREATE INDEX idx_sessions_active ON sessions(terminated_at) WHERE terminated_at IS NULL;
