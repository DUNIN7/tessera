// =============================================================================
// TESSERA — Layer Guard Middleware
//
// Structural enforcement of the two-layer role model.
// (Parallel Architecture Evaluation §9)
//
// Content-layer roles CANNOT invoke access-control-layer operations.
// Access-control-layer roles CANNOT invoke content-layer operations.
//
// This is applied at the route-group level:
//   /api/content/*        → requireLayer('content')
//   /api/access-control/* → requireLayer('access_control')
//
// The separation ensures "compromise of any content role reveals nothing
// about authorization, and vice versa." (Parallel Eval §9)
// =============================================================================

import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../types/auth';
import { RoleLayer } from '../types/roles';

/**
 * Returns middleware that verifies the user operates in the required
 * structural layer. Must be used AFTER authenticate middleware.
 *
 * Unlike role-guard (which checks specific roles), layer-guard checks
 * whether ANY of the user's roles belong to the required layer.
 * This prevents an access-control-layer user from accessing content
 * routes even if they somehow acquired a valid JWT.
 */
export function requireLayer(layer: RoleLayer) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    if (!req.user.layers.includes(layer)) {
      res.status(403).json({
        error: 'Operation not permitted for your role layer',
        requiredLayer: layer,
        yourLayers: req.user.layers,
      });
      return;
    }

    next();
  };
}
