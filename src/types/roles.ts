// =============================================================================
// TESSERA — Role Definitions
//
// Eight roles across two structural layers.
// Tessera v3.1 §4 + Parallel Architecture Evaluation §9
// =============================================================================

/** All roles in the system */
export type UserRole =
  // Content layer (Tessera v3.1 §4)
  | 'system_admin'
  | 'org_admin'
  | 'redactor'
  | 'reviewer'
  | 'viewer'
  | 'auditor'
  // Access-control layer (Parallel Eval §9)
  | 'acl_author'
  | 'asset_provisioner';

/** Structural layer a role belongs to */
export type RoleLayer = 'content' | 'access_control';

/**
 * Static mapping of roles to their structural layer.
 * Used by layer_guard middleware to enforce separation.
 * 
 * Content-layer roles CANNOT invoke access-control-layer operations.
 * Access-control-layer roles CANNOT invoke content-layer operations.
 * This is structural enforcement, not policy. (Parallel Eval §9)
 */
export const ROLE_LAYER_MAP: Record<UserRole, RoleLayer> = {
  system_admin:      'content',
  org_admin:         'content',
  redactor:          'content',
  reviewer:          'content',
  viewer:            'content',
  auditor:           'content',
  acl_author:        'access_control',
  asset_provisioner: 'access_control',
};

/** Content-layer roles */
export const CONTENT_ROLES: UserRole[] = [
  'system_admin', 'org_admin', 'redactor', 'reviewer', 'viewer', 'auditor',
];

/** Access-control-layer roles */
export const ACCESS_CONTROL_ROLES: UserRole[] = [
  'acl_author', 'asset_provisioner',
];

/**
 * Roles that require hardware security tokens (FIDO2/WebAuthn).
 * (Tessera v3.1 §10.4)
 */
export const HARDWARE_TOKEN_REQUIRED: UserRole[] = [
  'system_admin', 'org_admin', 'redactor', 'reviewer',
  'acl_author', 'asset_provisioner',
];

/**
 * Roles that have NO access to document content or encryption keys.
 * Structural prohibition, not policy. (Tessera v3.1 §4)
 */
export const NO_CONTENT_ACCESS: UserRole[] = [
  'system_admin', 'auditor', 'acl_author', 'asset_provisioner',
];
