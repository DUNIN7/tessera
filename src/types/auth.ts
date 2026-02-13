// =============================================================================
// TESSERA — Authentication Types
// =============================================================================

import { Request } from 'express';
import { UserRole, RoleLayer } from './roles';

/** JWT payload stored in the token */
export interface JwtPayload {
  /** User ID */
  sub: string;
  /** JWT ID — unique token identifier, maps to sessions.token_id */
  jti: string;
  /** Organization ID — tenant scope */
  org: string;
  /** Roles assigned to this user */
  roles: UserRole[];
  /** Layers this user can operate in (derived from roles) */
  layers: RoleLayer[];
  /** Issued at (epoch seconds) */
  iat: number;
  /** Expires at (epoch seconds) */
  exp: number;
}

/** Express request extended with authenticated user data */
export interface AuthenticatedRequest extends Request {
  user: {
    id: string;
    organizationId: string;
    email: string;
    displayName: string;
    roles: UserRole[];
    layers: RoleLayer[];
    sessionId: string;
    tokenId: string;
  };
}

/** Authorization tier for the current request's organization */
export type AuthorizationTier = 'tier_1' | 'tier_2' | 'tier_3';
