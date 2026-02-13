// =============================================================================
// TESSERA — Tenant Isolation Middleware
//
// Ensures all data access is scoped to the authenticated user's organization.
// (Tessera v3.1 §3.3: "Tenant isolation enforced at the infrastructure level.")
//
// System admins may access cross-org data for platform management;
// all other roles are strictly org-scoped.
// =============================================================================

import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../types/auth';

/**
 * Enforces that route parameters referencing an organization match
 * the authenticated user's organization. System admins bypass this
 * for platform management operations.
 */
export function enforceTenantIsolation(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  if (!req.user) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  // System admins can operate across organizations (platform management only —
  // they still have NO document content or key access per §4).
  if (req.user.roles.includes('system_admin')) {
    next();
    return;
  }

  // Check if the route targets a specific org (via param or body)
  const targetOrg = req.params.organizationId || req.body?.organizationId;

  if (targetOrg && targetOrg !== req.user.organizationId) {
    res.status(403).json({
      error: 'Access denied: cross-organization operation not permitted',
    });
    return;
  }

  next();
}
