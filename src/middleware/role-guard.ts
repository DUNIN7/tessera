// =============================================================================
// TESSERA — Role Guard Middleware
//
// Verifies the authenticated user holds at least one of the required roles.
// Used on individual routes: requireRole('org_admin', 'system_admin')
// (Tessera v3.1 §4)
// =============================================================================

import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../types/auth';
import { UserRole } from '../types/roles';

/**
 * Returns middleware that verifies the user has at least one of the
 * specified roles. Must be used AFTER authenticate middleware.
 */
export function requireRole(...roles: UserRole[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    const hasRole = req.user.roles.some((r) => roles.includes(r));
    if (!hasRole) {
      res.status(403).json({
        error: 'Insufficient permissions',
        required: roles,
        current: req.user.roles,
      });
      return;
    }

    next();
  };
}
