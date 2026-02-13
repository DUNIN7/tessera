// =============================================================================
// TESSERA — Security Hardening Middleware
//
// Phase 6: Production-grade security middleware stack.
//
// Covers:
//   - Rate limiting (per-IP and per-user)
//   - Security headers (CSP, HSTS, X-Frame-Options, etc.)
//   - CORS configuration
//   - Session enforcement (§10.4: 15-min timeout, no remember-me)
//   - Request validation and sanitization
//   - Error handling (no stack traces in production)
// =============================================================================

import { Request, Response, NextFunction, RequestHandler } from 'express';

// ── Rate Limiting ──────────────────────────────────────────────────────

/**
 * Simple in-memory rate limiter.
 * Production: use Redis-backed rate limiting.
 */
const rateLimitStore = new Map<string, { count: number; windowStart: number }>();

export function rateLimit(options: {
  windowMs: number;
  maxRequests: number;
  keyFn?: (req: Request) => string;
}): RequestHandler {
  const { windowMs, maxRequests, keyFn } = options;

  return (req: Request, res: Response, next: NextFunction) => {
    const key = keyFn ? keyFn(req) : (req.ip || 'unknown');
    const now = Date.now();

    const entry = rateLimitStore.get(key);
    if (!entry || now - entry.windowStart > windowMs) {
      rateLimitStore.set(key, { count: 1, windowStart: now });
      return next();
    }

    entry.count++;
    if (entry.count > maxRequests) {
      res.set('Retry-After', String(Math.ceil((windowMs - (now - entry.windowStart)) / 1000)));
      res.status(429).json({
        error: 'Too many requests',
        retryAfter: Math.ceil((windowMs - (now - entry.windowStart)) / 1000),
      });
      return;
    }

    next();
  };
}

/** Clean up expired rate limit entries every 5 minutes */
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore) {
    if (now - entry.windowStart > 300000) rateLimitStore.delete(key);
  }
}, 300000);

// ── Security Headers ───────────────────────────────────────────────────

/**
 * Security headers middleware. Equivalent to helmet but zero-dependency.
 */
export function securityHeaders(): RequestHandler {
  return (_req: Request, res: Response, next: NextFunction) => {
    // Prevent clickjacking
    res.set('X-Frame-Options', 'DENY');

    // Prevent MIME type sniffing
    res.set('X-Content-Type-Options', 'nosniff');

    // XSS protection (legacy browsers)
    res.set('X-XSS-Protection', '1; mode=block');

    // Strict Transport Security (1 year, include subdomains)
    res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');

    // Content Security Policy — strict
    res.set('Content-Security-Policy', [
      "default-src 'none'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "font-src 'self'",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join('; '));

    // Referrer Policy
    res.set('Referrer-Policy', 'strict-origin-when-cross-origin');

    // Permissions Policy — disable sensitive browser features
    res.set('Permissions-Policy', [
      'camera=()',
      'microphone=()',
      'geolocation=()',
      'payment=()',
    ].join(', '));

    // Cache control — no caching of authenticated content
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');

    next();
  };
}

// ── CORS Configuration ─────────────────────────────────────────────────

/**
 * CORS middleware with strict origin checking.
 */
export function corsPolicy(allowedOrigins: string[]): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const origin = req.get('Origin');

    if (origin && allowedOrigins.includes(origin)) {
      res.set('Access-Control-Allow-Origin', origin);
      res.set('Access-Control-Allow-Credentials', 'true');
      res.set('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
      res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Request-ID');
      res.set('Access-Control-Max-Age', '600');
      res.set('Vary', 'Origin');
    }

    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }

    next();
  };
}

// ── Session Enforcement (§10.4) ────────────────────────────────────────

/**
 * Session timeout enforcement. (§10.4)
 * "Short-lived sessions (default 15 min inactivity timeout);
 *  mandatory re-authentication. No persistent sessions or 'remember me'."
 */
const sessionActivity = new Map<string, number>();

export function sessionTimeout(
  timeoutMs: number = 15 * 60 * 1000 // 15 minutes default (§10.4)
): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const userId = (req as any).user?.id;
    if (!userId) return next(); // Pre-auth route

    const lastActivity = sessionActivity.get(userId);
    const now = Date.now();

    if (lastActivity && now - lastActivity > timeoutMs) {
      sessionActivity.delete(userId);
      res.status(401).json({
        error: 'Session expired due to inactivity',
        code: 'SESSION_TIMEOUT',
        reauthRequired: true,
      });
      return;
    }

    sessionActivity.set(userId, now);
    next();
  };
}

/** Clean up stale session entries */
setInterval(() => {
  const staleThreshold = Date.now() - 30 * 60 * 1000;
  for (const [key, ts] of sessionActivity) {
    if (ts < staleThreshold) sessionActivity.delete(key);
  }
}, 60000);

// ── Input Validation ───────────────────────────────────────────────────

/**
 * Request body size limit and basic sanitization.
 */
export function requestSanitization(): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    // Reject oversized JSON bodies (beyond Express's built-in limit)
    const contentLength = parseInt(req.get('Content-Length') || '0');
    if (contentLength > 50 * 1024 * 1024) { // 50MB for non-file uploads
      res.status(413).json({ error: 'Request body too large' });
      return;
    }

    // Strip null bytes from string values in body
    if (req.body && typeof req.body === 'object') {
      sanitizeObject(req.body);
    }

    next();
  };
}

function sanitizeObject(obj: any): void {
  for (const key of Object.keys(obj)) {
    if (typeof obj[key] === 'string') {
      obj[key] = obj[key].replace(/\0/g, '');
    } else if (obj[key] && typeof obj[key] === 'object') {
      sanitizeObject(obj[key]);
    }
  }
}

// ── Request ID ─────────────────────────────────────────────────────────

/**
 * Assign a unique request ID for tracing.
 */
export function requestId(): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const id = req.get('X-Request-ID') || `tess-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    res.set('X-Request-ID', id);
    (req as any).requestId = id;
    next();
  };
}

// ── Error Handler ──────────────────────────────────────────────────────

/**
 * Global error handler. Never leaks stack traces in production.
 */
export function errorHandler() {
  return (err: Error, _req: Request, res: Response, _next: NextFunction) => {
    const isProd = process.env.NODE_ENV === 'production';

    console.error(`[ERROR] ${err.message}`, isProd ? '' : err.stack);

    res.status(500).json({
      error: isProd ? 'Internal server error' : err.message,
      ...(isProd ? {} : { stack: err.stack }),
    });
  };
}
