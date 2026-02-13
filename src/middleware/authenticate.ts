// =============================================================================
// TESSERA — Authentication Middleware
//
// Verifies JWT, enforces session inactivity timeout (Tessera v3.1 §10.4),
// and attaches authenticated user data to the request.
// =============================================================================

import { Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { pool } from '../db/pool';
import { config } from '../config';
import { JwtPayload, AuthenticatedRequest } from '../types/auth';

/**
 * Authenticate incoming requests via JWT Bearer token.
 * Enforces:
 *   - Valid JWT signature and expiration
 *   - Active session in database (not terminated)
 *   - Inactivity timeout per organization security profile (§10.4)
 *   - No persistent sessions or "remember me" (§10.4)
 */
export async function authenticate(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  const token = authHeader.slice(7);

  try {
    // Verify JWT
    const payload = jwt.verify(token, config.jwt.secret) as JwtPayload;

    // Check session is still active (not terminated by logout or forced expiry)
    const sessionResult = await pool.query(
      `SELECT s.id, s.last_activity, sp.session_timeout_seconds
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       LEFT JOIN security_profiles sp ON sp.organization_id = u.organization_id
       WHERE s.token_id = $1 AND s.terminated_at IS NULL`,
      [payload.jti]
    );

    if (sessionResult.rows.length === 0) {
      res.status(401).json({ error: 'Session expired or terminated' });
      return;
    }

    const session = sessionResult.rows[0];
    const timeoutSeconds = session.session_timeout_seconds || config.session.inactivityTimeoutSeconds;
    const lastActivity = new Date(session.last_activity);
    const elapsed = (Date.now() - lastActivity.getTime()) / 1000;

    // Enforce inactivity timeout (§10.4: default 15 min)
    if (elapsed > timeoutSeconds) {
      // Terminate the session
      await pool.query(
        `UPDATE sessions SET terminated_at = now() WHERE id = $1`,
        [session.id]
      );
      res.status(401).json({ error: 'Session timed out due to inactivity' });
      return;
    }

    // Update last activity (session is alive)
    await pool.query(
      `UPDATE sessions SET last_activity = now() WHERE id = $1`,
      [session.id]
    );

    // Attach user data to request
    (req as AuthenticatedRequest).user = {
      id: payload.sub,
      organizationId: payload.org,
      email: '', // Populated if needed from DB
      displayName: '',
      roles: payload.roles,
      layers: payload.layers,
      sessionId: session.id,
      tokenId: payload.jti,
    };

    next();
  } catch (err: any) {
    if (err.name === 'TokenExpiredError') {
      res.status(401).json({ error: 'Token expired' });
    } else if (err.name === 'JsonWebTokenError') {
      res.status(401).json({ error: 'Invalid token' });
    } else {
      res.status(500).json({ error: 'Authentication error' });
    }
  }
}
