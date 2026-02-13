-- =============================================================================
-- TESSERA — Phase 5+6 Schema Additions
--
-- Tables for export/watermarking (§9.3, §10.5), viewing sessions (§11.2),
-- retention policies (§12), and document versioning (§14).
-- Mount as /docker-entrypoint-initdb.d/04-phase56-schema.sql
-- =============================================================================

-- =============================================================================
-- EXPORT EVENTS (§9.3, §10.5)
-- =============================================================================

CREATE TABLE export_events (
  id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id               UUID NOT NULL REFERENCES documents(id),
  organization_id           UUID NOT NULL REFERENCES organizations(id),
  viewer_id                 UUID NOT NULL REFERENCES users(id),
  access_level_id           UUID NOT NULL,
  reconstruction_event_id   UUID NOT NULL REFERENCES reconstruction_events(id),
  format                    VARCHAR(20) NOT NULL,
  content_hash              VARCHAR(128) NOT NULL,
  watermark_payload         JSONB NOT NULL,
  foray_tx_id               VARCHAR(255),
  created_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_export_events_doc ON export_events(document_id);
CREATE INDEX idx_export_events_viewer ON export_events(viewer_id);
CREATE INDEX idx_export_events_org ON export_events(organization_id);

-- =============================================================================
-- VIEWING SESSIONS (§11.2 Viewing level)
-- =============================================================================

CREATE TABLE viewing_sessions (
  id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  reconstruction_event_id   UUID NOT NULL REFERENCES reconstruction_events(id),
  document_id               UUID NOT NULL REFERENCES documents(id),
  viewer_id                 UUID NOT NULL REFERENCES users(id),
  access_level_id           UUID NOT NULL,
  organization_id           UUID NOT NULL REFERENCES organizations(id),
  pages_viewed              JSONB NOT NULL DEFAULT '[]',
  duration_seconds          INT,
  navigation_events         JSONB NOT NULL DEFAULT '[]',
  created_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_viewing_sessions_doc ON viewing_sessions(document_id);
CREATE INDEX idx_viewing_sessions_viewer ON viewing_sessions(viewer_id);

-- =============================================================================
-- RETENTION POLICIES (§12.1)
-- =============================================================================

CREATE TABLE retention_policies (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  classification      VARCHAR(100) NOT NULL UNIQUE,
  regulation_name     VARCHAR(255) NOT NULL,
  jurisdiction        VARCHAR(100),
  min_retention_days  INT NOT NULL,
  description         TEXT,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed some common regulatory retention floors
INSERT INTO retention_policies (classification, regulation_name, jurisdiction, min_retention_days, description) VALUES
  ('financial_records',  'SOX',           'US',     2555,  'Sarbanes-Oxley: 7 years for financial records'),
  ('health_records',     'HIPAA',         'US',     2190,  'HIPAA: 6 years from creation or last effective date'),
  ('personal_data_eu',   'GDPR',          'EU',     0,     'GDPR: No fixed minimum; subject to erasure requests'),
  ('tax_records',        'IRS',           'US',     2555,  'IRS: 7 years for tax-related documents'),
  ('defense_technical',  'ITAR',          'US',     1825,  'ITAR: 5 years minimum for defense technical data'),
  ('employee_records',   'EEOC',          'US',     365,   'EEOC: 1 year minimum for employment records'),
  ('cui',               'NIST SP 800-171','US',     1095,  'CUI: 3 years minimum retention');

-- =============================================================================
-- DOCUMENT VERSIONING COLUMNS (§14)
-- =============================================================================

-- Add version tracking columns to documents table.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'documents' AND column_name = 'version_number'
  ) THEN
    ALTER TABLE documents ADD COLUMN version_number INT NOT NULL DEFAULT 1;
    ALTER TABLE documents ADD COLUMN version_chain_id UUID;
    ALTER TABLE documents ADD COLUMN previous_version_id UUID REFERENCES documents(id);
  END IF;

  -- Add retention and legal hold columns
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'documents' AND column_name = 'regulatory_classification'
  ) THEN
    ALTER TABLE documents ADD COLUMN regulatory_classification VARCHAR(100);
    ALTER TABLE documents ADD COLUMN legal_hold BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE documents ADD COLUMN legal_hold_reason TEXT;
  END IF;

  -- Add export_permitted to security_profiles
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'security_profiles' AND column_name = 'export_permitted'
  ) THEN
    ALTER TABLE security_profiles ADD COLUMN export_permitted BOOLEAN NOT NULL DEFAULT true;
    ALTER TABLE security_profiles ADD COLUMN default_retention_days INT NOT NULL DEFAULT 2555;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_documents_chain ON documents(version_chain_id);
CREATE INDEX IF NOT EXISTS idx_documents_prev ON documents(previous_version_id);
