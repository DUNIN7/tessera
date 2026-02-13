-- =============================================================================
-- TESSERA — Development Seed Data
--
-- Creates example organizations, users, roles, security profiles, and
-- access levels for local development and testing.
--
-- All passwords are bcrypt hash of 'tessera-dev-password'.
-- All emails use @example.com per RFC 2606.
-- =============================================================================

-- Organizations
INSERT INTO organizations (id, name, slug) VALUES
  ('a0000000-0000-0000-0000-000000000001', 'Acme Defense Corp', 'acme-defense'),
  ('a0000000-0000-0000-0000-000000000002', 'Global Health Partners', 'global-health');

-- Security profiles: Acme = Tier 1, Global Health = Tier 2 (future Ova)
INSERT INTO security_profiles (organization_id, auth_tier, storage_tier, key_split_m, key_split_n, export_permitted, session_timeout_seconds) VALUES
  ('a0000000-0000-0000-0000-000000000001', 'tier_1', 'tier_1', 2, 3, true, 900),
  ('a0000000-0000-0000-0000-000000000002', 'tier_2', 'tier_2', 3, 5, false, 600);

-- Users (password: 'tessera-dev-password' → bcrypt)
-- Hash generated with cost factor 10
INSERT INTO users (id, organization_id, email, password_hash, display_name, mfa_enrolled, hardware_token_registered) VALUES
  -- System admin (no org-specific content access)
  ('b0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001',
   'sysadmin@example.com',
   '$2a$10$X7UrE3PkQZ5FVnQVqGhzF.FgVL6QKBKWJ1tqK4YzOjKhJX0Dm3ty',
   'System Administrator', true, true),
  
  -- Acme org admin
  ('b0000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000001',
   'admin@example.com',
   '$2a$10$X7UrE3PkQZ5FVnQVqGhzF.FgVL6QKBKWJ1tqK4YzOjKhJX0Dm3ty',
   'Acme Admin', true, true),
  
  -- Acme redactor
  ('b0000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000001',
   'redactor@example.com',
   '$2a$10$X7UrE3PkQZ5FVnQVqGhzF.FgVL6QKBKWJ1tqK4YzOjKhJX0Dm3ty',
   'Acme Redactor', true, true),
  
  -- Acme reviewer
  ('b0000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000001',
   'reviewer@example.com',
   '$2a$10$X7UrE3PkQZ5FVnQVqGhzF.FgVL6QKBKWJ1tqK4YzOjKhJX0Dm3ty',
   'Acme Reviewer', true, true),
  
  -- Acme viewer
  ('b0000000-0000-0000-0000-000000000005', 'a0000000-0000-0000-0000-000000000001',
   'viewer@example.com',
   '$2a$10$X7UrE3PkQZ5FVnQVqGhzF.FgVL6QKBKWJ1tqK4YzOjKhJX0Dm3ty',
   'Acme Viewer', true, false),
  
  -- Acme auditor
  ('b0000000-0000-0000-0000-000000000006', 'a0000000-0000-0000-0000-000000000001',
   'auditor@example.com',
   '$2a$10$X7UrE3PkQZ5FVnQVqGhzF.FgVL6QKBKWJ1tqK4YzOjKhJX0Dm3ty',
   'Acme Auditor', true, false),
  
  -- Acme ACL author (access-control layer)
  ('b0000000-0000-0000-0000-000000000007', 'a0000000-0000-0000-0000-000000000001',
   'acl-author@example.com',
   '$2a$10$X7UrE3PkQZ5FVnQVqGhzF.FgVL6QKBKWJ1tqK4YzOjKhJX0Dm3ty',
   'Acme ACL Author', true, true),
  
  -- Acme asset provisioner (access-control layer)
  ('b0000000-0000-0000-0000-000000000008', 'a0000000-0000-0000-0000-000000000001',
   'asset-provisioner@example.com',
   '$2a$10$X7UrE3PkQZ5FVnQVqGhzF.FgVL6QKBKWJ1tqK4YzOjKhJX0Dm3ty',
   'Acme Asset Provisioner', true, true);

-- Role assignments with layer derivation
INSERT INTO user_roles (user_id, role, layer) VALUES
  ('b0000000-0000-0000-0000-000000000001', 'system_admin',      'content'),
  ('b0000000-0000-0000-0000-000000000002', 'org_admin',         'content'),
  ('b0000000-0000-0000-0000-000000000003', 'redactor',          'content'),
  ('b0000000-0000-0000-0000-000000000004', 'reviewer',          'content'),
  ('b0000000-0000-0000-0000-000000000005', 'viewer',            'content'),
  ('b0000000-0000-0000-0000-000000000006', 'auditor',           'content'),
  ('b0000000-0000-0000-0000-000000000007', 'acl_author',        'access_control'),
  ('b0000000-0000-0000-0000-000000000008', 'asset_provisioner', 'access_control');
