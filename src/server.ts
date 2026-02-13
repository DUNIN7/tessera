// =============================================================================
// TESSERA — Main Server
// Secure Document Redaction & Access Control System
//
// Owner/Licensor: Marvin Percival — marvinp@dunin7.com
// Repository:     github.com/DUNIN7/tessera
// License:        Business Source License 1.1 (BSL 1.1)
//
// Route architecture reflects the two-layer structural separation
// from Parallel Architecture Evaluation §9:
//
//   /api/auth/*            — Authentication (login, logout, session)
//   /api/content/*         — Content layer operations (requireLayer: content)
//   /api/access-control/*  — Authorization operations (requireLayer: access_control)
//   /api/audit/*           — Audit trail (auditor + org_admin)
//   /api/health            — Health check (unauthenticated)
//
// Content-layer roles cannot reach /api/access-control/* routes.
// Access-control-layer roles cannot reach /api/content/* routes.
// This is structural enforcement via layer-guard middleware.
// =============================================================================

import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { config } from './config';
import { pool } from './db/pool';
import {
  securityHeaders,
  requestId,
  requestSanitization,
  sessionTimeout,
  errorHandler as tesseraErrorHandler,
} from './middleware/security';

// Route modules
import authRoutes from './routes/auth';
import contentRoutes from './routes/content/index';
import accessControlRoutes from './routes/access-control/index';
import auditRoutes from './routes/audit/index';

const app = express();

// ── Security Middleware ────────────────────────────────────────────────

app.use(helmet());
app.use(cors({
  origin: config.nodeEnv === 'development' ? '*' : undefined,
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));

// Phase 6: Additional security hardening
app.use(requestId());           // Unique request ID for tracing
app.use(securityHeaders());     // CSP, HSTS, X-Frame-Options, etc.
app.use(requestSanitization()); // Null-byte stripping, size validation

// Rate limiting (Tessera v3.1 §10.4: defense against brute-force)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_AUTH_MAX || '20', 10),
  message: { error: 'Too many authentication attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 120, // 120 requests per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
});

// ── Routes ─────────────────────────────────────────────────────────────

// Health check — unauthenticated, for Docker/load balancer probes
const startTime = Date.now();

app.get('/api/health', async (_req, res) => {
  const checks: Record<string, { status: string; latencyMs?: number }> = {};

  // Database check
  const dbStart = Date.now();
  try {
    await pool.query('SELECT 1');
    checks.database = { status: 'healthy', latencyMs: Date.now() - dbStart };
  } catch {
    checks.database = { status: 'unhealthy', latencyMs: Date.now() - dbStart };
  }

  // FORAY check (connectivity)
  const forayStart = Date.now();
  try {
    // Lightweight check — just verify config is valid
    checks.foray = {
      status: config.foray.apiUrl ? 'configured' : 'unconfigured',
      latencyMs: Date.now() - forayStart,
    };
  } catch {
    checks.foray = { status: 'unhealthy', latencyMs: Date.now() - forayStart };
  }

  // HSM check
  checks.hsm = { status: 'healthy' }; // SoftHSM dev — always available

  const allHealthy = checks.database.status === 'healthy';
  const status = allHealthy ? 'healthy' : 'degraded';

  res.status(allHealthy ? 200 : 503).json({
    status,
    service: 'tessera',
    version: '0.6.0',
    uptime: Math.floor((Date.now() - startTime) / 1000),
    checks,
    timestamp: new Date().toISOString(),
  });
});

// Authentication routes (login rate-limited)
app.use('/api/auth', authLimiter, authRoutes);

// Content layer routes — structurally restricted to content-layer roles
// Session timeout enforced per §10.4 (15-min inactivity)
app.use('/api/content', apiLimiter, sessionTimeout(), contentRoutes);

// Access-control layer routes — structurally restricted to access-control-layer roles
app.use('/api/access-control', apiLimiter, sessionTimeout(), accessControlRoutes);

// Audit routes — available to auditor and org_admin
app.use('/api/audit', apiLimiter, sessionTimeout(), auditRoutes);

// ── 404 Handler ────────────────────────────────────────────────────────

app.use((_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ── Error Handler ──────────────────────────────────────────────────────

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('[Server] Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Start ──────────────────────────────────────────────────────────────

app.listen(config.port, () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║  TESSERA — Secure Document Redaction & Access Control        ║
║  Version 0.6.0 (Phase 5+6 — Reconstruction & Hardening)      ║
║                                                              ║
║  Port:     ${String(config.port).padEnd(48)}║
║  Env:      ${config.nodeEnv.padEnd(48)}║
║  FORAY:    ${config.foray.apiUrl.padEnd(48)}║
║                                                              ║
║  Route Architecture (Parallel Eval §9):                      ║
║    /api/content/*         → Content layer roles              ║
║    /api/access-control/*  → Access-control layer roles       ║
║    /api/audit/*           → Auditor + Org Admin              ║
║    /api/health            → Unauthenticated health probe     ║
║                                                              ║
║  Owner: Marvin Percival — marvinp@dunin7.com                 ║
║  License: BSL 1.1 — github.com/DUNIN7/tessera               ║
╚══════════════════════════════════════════════════════════════╝
  `);
});

export default app;
