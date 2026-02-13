// =============================================================================
// TESSERA — Authentication Routes
//
// Login, logout, and session management.
// (Tessera v3.1 §10.4: MFA mandatory, short-lived sessions,
//  no persistent sessions, no "remember me")
//
// Note: MFA and FIDO2/WebAuthn enforcement is stubbed for Phase 1.
// Production implementation requires actual FIDO2 ceremony integration.
// =============================================================================

import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { pool } from '../db/pool';
import { config } from '../config';
import { ROLE_LAYER_MAP, UserRole, RoleLayer } from '../types/roles';
import { authenticate } from '../middleware/authenticate';
import { AuthenticatedRequest } from '../types/auth';
import { recordAuditEvent } from '../services/audit';

const router = Router();

/**
 * POST /api/auth/login
 * Authenticate with email and password. Returns JWT.
 *
 * Phase 1: Password-only. Production adds MFA challenge step.
 */
router.post('/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).json({ error: 'Email and password required' });
    return;
  }

  try {
    // Fetch user with roles
    const userResult = await pool.query(
      `SELECT u.id, u.organization_id, u.email, u.display_name,
              u.password_hash, u.mfa_enrolled, u.is_active
       FROM users u
       WHERE u.email = $1`,
      [email]
    );

    if (userResult.rows.length === 0) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const user = userResult.rows[0];

    if (!user.is_active) {
      res.status(401).json({ error: 'Account deactivated' });
      return;
    }

    // Verify password
    const passwordValid = await bcrypt.compare(password, user.password_hash);
    if (!passwordValid) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    // Fetch roles
    const rolesResult = await pool.query(
      `SELECT role, layer FROM user_roles WHERE user_id = $1`,
      [user.id]
    );

    const roles: UserRole[] = rolesResult.rows.map((r: any) => r.role);
    const layers: RoleLayer[] = [...new Set(rolesResult.rows.map((r: any) => r.layer))];

    // Create session
    const tokenId = uuidv4();
    const sessionId = uuidv4();

    await pool.query(
      `INSERT INTO sessions (id, user_id, token_id, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        sessionId,
        user.id,
        tokenId,
        req.ip || null,
        req.headers['user-agent'] || null,
      ]
    );

    // Generate JWT
    // @ts-ignore — jwt.sign overload types incompatible with string config values    const token = (jwt.sign as any)(
      {
        sub: user.id,
        jti: tokenId,
        org: user.organization_id,
        roles,
        layers,
      },
      config.jwt.secret,
      { expiresIn: config.jwt.expiry }
    );

    // Audit: login event
    await recordAuditEvent({
      category: 'action',
      eventType: 'user.login',
      description: `User ${user.email} logged in`,
      organizationId: user.organization_id,
      actorId: user.id,
      actorRole: roles[0],
      actorLayer: layers[0],
      targetType: 'user',
      targetId: user.id,
      metadata: { ip: req.ip, userAgent: req.headers['user-agent'] },
    });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        displayName: user.display_name,
        organizationId: user.organization_id,
        roles,
        layers,
      },
    });
  } catch (err: any) {
    console.error('[Auth] Login error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/auth/logout
 * Terminate the current session. (Tessera v3.1 §10.4)
 */
router.post(
  '/logout',
  authenticate as any,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      await pool.query(
        `UPDATE sessions SET terminated_at = now() WHERE token_id = $1`,
        [req.user.tokenId]
      );

      await recordAuditEvent({
        category: 'action',
        eventType: 'user.logout',
        description: `User logged out`,
        organizationId: req.user.organizationId,
        actorId: req.user.id,
        targetType: 'user',
        targetId: req.user.id,
      });

      res.json({ message: 'Logged out' });
    } catch (err: any) {
      console.error('[Auth] Logout error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * GET /api/auth/session
 * Return current session info. Useful for frontend session status checks.
 */
router.get(
  '/session',
  authenticate as any,
  async (req: AuthenticatedRequest, res: Response) => {
    res.json({
      user: req.user,
      sessionActive: true,
    });
  }
);

export default router;
