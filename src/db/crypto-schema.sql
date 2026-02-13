-- =============================================================================
-- TESSERA — Phase 4 Schema Additions: Crypto Core
--
-- Tables for encryption key management, encrypted content set storage,
-- base documents with positional markers, Shamir share tracking, and
-- reconstruction events.
-- (Tessera v3.1 §8.3, §8.4, §9, §10)
--
-- Applied AFTER Phase 1 schema and Phase 3 markup schema.
-- Mount as /docker-entrypoint-initdb.d/03-crypto-schema.sql
-- =============================================================================

-- =============================================================================
-- ENCRYPTION KEYS
-- =============================================================================

-- Key metadata. Actual key material is in the HSM. (§10.2)
-- "Key generation: Within HSM; keys never in plaintext outside HSM"
-- "Insider threat control: System admins have no key access."
CREATE TABLE encryption_keys (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Document this key encrypts a content set for.
  document_id             UUID NOT NULL REFERENCES documents(id),

  -- Which content set this key is for. Unique key per content set. (§10.1)
  content_set_identifier  VARCHAR(50) NOT NULL,

  -- Organization (for tenant isolation).
  organization_id         UUID NOT NULL REFERENCES organizations(id),

  -- HSM handle for retrieving key material.
  -- In SoftHSM dev: "softhsm-{uuid}"
  -- In production: PKCS#11 object handle
  hsm_key_handle          VARCHAR(255) NOT NULL,

  -- Algorithm. (§10.1: "AES-256-GCM")
  algorithm               VARCHAR(50) NOT NULL DEFAULT 'aes-256-gcm',

  -- Shamir's Secret Sharing configuration. (§10.2)
  shamir_threshold        INT NOT NULL,      -- M: minimum shares to reconstruct
  shamir_total_shares     INT NOT NULL,      -- N: total shares distributed

  -- Key lifecycle state.
  is_active               BOOLEAN NOT NULL DEFAULT true,

  -- If rotated, the previous key ID. (§10.2: "Key rotation: re-encrypts
  -- without re-deconstruction")
  rotated_from_key_id     UUID REFERENCES encryption_keys(id),

  created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  rotated_at              TIMESTAMPTZ,
  destroyed_at            TIMESTAMPTZ           -- (§12.2 step 5)
);

CREATE INDEX idx_enc_keys_doc ON encryption_keys(document_id);
CREATE INDEX idx_enc_keys_active ON encryption_keys(document_id, content_set_identifier, is_active);
CREATE INDEX idx_enc_keys_org ON encryption_keys(organization_id);

-- =============================================================================
-- KEY SHARES (Shamir)
-- =============================================================================

-- Tracks Shamir share distribution. Share DATA is not stored here in
-- production — only metadata. Shares are distributed to designated
-- key holders. (§10.2: "Share distribution: To designated key holders;
-- cross-org distribution for trust groups")
CREATE TABLE key_shares (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Key this share belongs to.
  key_id          UUID NOT NULL REFERENCES encryption_keys(id) ON DELETE CASCADE,

  -- Share index (1-based, used as x-coordinate in Shamir polynomial).
  share_index     INT NOT NULL,

  -- Designated holder identifier.
  holder_id       VARCHAR(255) NOT NULL,

  -- Whether this share has been distributed to the holder.
  distributed     BOOLEAN NOT NULL DEFAULT false,
  distributed_at  TIMESTAMPTZ,

  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

  UNIQUE(key_id, share_index)
);

CREATE INDEX idx_key_shares_key ON key_shares(key_id);

-- =============================================================================
-- ENCRYPTED CONTENT SETS
-- =============================================================================

-- Encrypted content set storage. (§8.3 step 4-5)
-- "Each content set encrypted with AES-256-GCM using unique key."
-- "Each encrypted set stored in physically separate location."
--
-- In production, actual storage would be distributed across separate
-- data centers / facilities per storage tier. The database record
-- tracks the encrypted envelope and storage location metadata.
CREATE TABLE encrypted_content_sets (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Document this content set belongs to.
  document_id             UUID NOT NULL REFERENCES documents(id),

  -- Content set identifier.
  content_set_identifier  VARCHAR(50) NOT NULL,

  -- Organization (for tenant isolation).
  organization_id         UUID NOT NULL REFERENCES organizations(id),

  -- Full encrypted envelope (JSONB): IV, auth tag, ciphertext, hashes.
  encrypted_envelope      JSONB NOT NULL,

  -- SHA-512 hash of the ciphertext. (§9.2: integrity verification)
  ciphertext_hash         VARCHAR(128) NOT NULL,

  -- Storage location identifier.
  -- In production: URI to the separate storage location.
  storage_location_id     VARCHAR(255) NOT NULL,

  -- Storage tier from security profile. (§10.3)
  storage_tier            VARCHAR(20) NOT NULL DEFAULT 'tier_1',

  -- Key used to encrypt this set.
  key_id                  UUID NOT NULL REFERENCES encryption_keys(id),

  created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),

  UNIQUE(document_id, content_set_identifier)
);

CREATE INDEX idx_enc_sets_doc ON encrypted_content_sets(document_id);
CREATE INDEX idx_enc_sets_org ON encrypted_content_sets(organization_id);

-- =============================================================================
-- BASE DOCUMENTS
-- =============================================================================

-- The base document with all redactable content removed and
-- positional markers at each extraction point. (§8.3 step 1, §8.4)
CREATE TABLE base_documents (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Document this base belongs to.
  document_id     UUID NOT NULL REFERENCES documents(id) UNIQUE,

  -- Organization (for tenant isolation).
  organization_id UUID NOT NULL REFERENCES organizations(id),

  -- Base document content with positional markers.
  content         TEXT NOT NULL,

  -- SHA-512 hash of the base document content. (§9.2)
  content_hash    VARCHAR(128) NOT NULL,

  -- Positional markers array (JSONB). (§8.4)
  markers         JSONB NOT NULL,

  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_base_docs_doc ON base_documents(document_id);
CREATE INDEX idx_base_docs_org ON base_documents(organization_id);

-- =============================================================================
-- RECONSTRUCTION EVENTS
-- =============================================================================

-- Every reconstruction is logged. (§9, §11.2 Viewing level)
-- "User, document, access level, timestamp, pages viewed,
-- duration, navigation" — recorded for behavioral audit.
--
-- "Reconstruction audit events must record the marker width setting
-- active at time of reconstruction." (Marker Width Amendment)
CREATE TABLE reconstruction_events (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Document that was reconstructed.
  document_id             UUID NOT NULL REFERENCES documents(id),

  -- Organization (for tenant isolation).
  organization_id         UUID NOT NULL REFERENCES organizations(id),

  -- Viewer who requested the reconstruction.
  viewer_id               UUID NOT NULL REFERENCES users(id),

  -- Access level used for this reconstruction.
  access_level_id         UUID NOT NULL,

  -- Content sets that were used (decrypted and visible).
  content_sets_used       JSONB NOT NULL DEFAULT '[]',

  -- Content sets that were redacted (viewer lacks access).
  content_sets_redacted   JSONB NOT NULL DEFAULT '[]',

  -- Marker width at time of reconstruction. (Marker Width Amendment)
  marker_width            INT NOT NULL DEFAULT 3,

  -- SHA-512 hash of the reconstructed view.
  reconstruction_hash     VARCHAR(128) NOT NULL,

  -- Whether all integrity checks passed. (§9.2)
  integrity_all_passed    BOOLEAN NOT NULL DEFAULT true,

  -- FORAY transaction ID.
  foray_tx_id             VARCHAR(255),

  created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_recon_events_doc ON reconstruction_events(document_id);
CREATE INDEX idx_recon_events_viewer ON reconstruction_events(viewer_id);
CREATE INDEX idx_recon_events_org ON reconstruction_events(organization_id);

-- =============================================================================
-- SECURITY PROFILE ADDITIONS
-- =============================================================================

-- Add marker_width column to security_profiles if not exists.
-- (Marker Width Amendment to §10.6)
-- "Redaction marker display width (3–10 characters; default: 3)"
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'security_profiles' AND column_name = 'marker_width'
  ) THEN
    ALTER TABLE security_profiles ADD COLUMN marker_width INT NOT NULL DEFAULT 3
      CHECK (marker_width >= 3 AND marker_width <= 10);
  END IF;
END $$;
