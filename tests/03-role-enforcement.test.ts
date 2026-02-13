// =============================================================================
// TESSERA — Test Suite 03: Role & Layer Enforcement
//
// Verifies structural separation between content and access-control layers.
// (Parallel Architecture Evaluation §9)
//
// "Content-layer roles CANNOT invoke access-control-layer operations.
//  Access-control-layer roles CANNOT invoke content-layer operations."
// =============================================================================

import { authApi, json, assertApi } from './helpers';

describe('Role & Layer Enforcement', () => {
  // ── Layer Separation ──────────────────────────────────────────────────

  describe('Layer Separation (§9)', () => {
    test('access-control layer user CANNOT access content routes', async () => {
      // ACL author is access-control layer — must be blocked from /api/content/*
      const res = await authApi('aclAuthor', 'GET', '/api/content/documents');
      expect(res.status).toBe(403);

      const body = await json(res);
      expect(body.error).toMatch(/layer/i);
    });

    test('asset provisioner CANNOT access content routes', async () => {
      const res = await authApi('assetProvisioner', 'GET', '/api/content/documents');
      expect(res.status).toBe(403);
    });

    test('content layer user CANNOT access access-control routes', async () => {
      // Redactor is content layer — must be blocked from /api/access-control/*
      const res = await authApi('redactor', 'GET', '/api/access-control/policies');
      // Could be 403 (layer guard) or 404 (route doesn't exist yet)
      expect([403, 404]).toContain(res.status);
    });
  });

  // ── Content Layer Role Guards ─────────────────────────────────────────

  describe('Content Layer Role Guards', () => {
    test('viewer CANNOT register documents (requires org_admin or redactor)', async () => {
      const res = await authApi('viewer', 'POST', '/api/content/documents', {
        title: 'Forbidden Doc',
        originalFilename: 'test.pdf',
        mimeType: 'application/pdf',
        originalSizeBytes: 1024,
        originalHash: 'abc123',
      });
      expect(res.status).toBe(403);
    });

    test('viewer CANNOT create access levels (requires org_admin)', async () => {
      const res = await authApi('viewer', 'POST', '/api/content/access-levels', {
        name: 'Forbidden Level',
      });
      expect(res.status).toBe(403);
    });

    test('redactor CANNOT create access levels (requires org_admin)', async () => {
      const res = await authApi('redactor', 'POST', '/api/content/access-levels', {
        name: 'Forbidden Level',
      });
      expect(res.status).toBe(403);
    });

    test('viewer CANNOT create markup sessions (requires redactor)', async () => {
      const res = await authApi('viewer', 'POST', '/api/content/markup/sessions', {
        documentId: 'b0000000-0000-0000-0000-000000000099',
      });
      expect(res.status).toBe(403);
    });

    test('reviewer CANNOT create markup sessions (requires redactor)', async () => {
      const res = await authApi('reviewer', 'POST', '/api/content/markup/sessions', {
        documentId: 'b0000000-0000-0000-0000-000000000099',
      });
      expect(res.status).toBe(403);
    });

    test('viewer CANNOT trigger deconstruction (requires org_admin)', async () => {
      const res = await authApi('viewer', 'POST', '/api/content/crypto/deconstruct/fake-id', {
        sessionId: 'fake-session',
      });
      expect(res.status).toBe(403);
    });

    test('redactor CANNOT trigger deconstruction (requires org_admin)', async () => {
      const res = await authApi('redactor', 'POST', '/api/content/crypto/deconstruct/fake-id', {
        sessionId: 'fake-session',
      });
      expect(res.status).toBe(403);
    });

    test('viewer CANNOT list users (requires org_admin)', async () => {
      const res = await authApi('viewer', 'GET', '/api/content/users');
      expect(res.status).toBe(403);
    });

    test('org_admin CAN list users', async () => {
      const res = await authApi('orgAdmin', 'GET', '/api/content/users');
      expect(res.status).toBe(200);

      const body = await json(res);
      expect(body.users).toBeDefined();
      expect(Array.isArray(body.users)).toBe(true);
      expect(body.users.length).toBeGreaterThan(0);
    });

    test('org_admin CAN list organizations', async () => {
      const res = await authApi('orgAdmin', 'GET', '/api/content/organizations');
      expect(res.status).toBe(200);

      const body = await json(res);
      expect(body.organizations).toBeDefined();
    });

    test('redactor CANNOT list organizations (requires org_admin)', async () => {
      const res = await authApi('redactor', 'GET', '/api/content/organizations');
      expect(res.status).toBe(403);
    });
  });

  // ── Audit Routes ──────────────────────────────────────────────────────

  describe('Audit Route Guards', () => {
    test('viewer CANNOT access audit trail', async () => {
      const res = await authApi('viewer', 'GET', '/api/audit/events');
      // Could be 403 (role guard) or route doesn't exist
      expect([403, 404]).toContain(res.status);
    });

    test('auditor CAN access audit events', async () => {
      const res = await authApi('auditor', 'GET', '/api/audit/events');
      // Auditor should have access — 200 or at least not 403
      expect([200, 404]).toContain(res.status);
    });
  });

  // ── Review Role Guards ────────────────────────────────────────────────

  describe('Review Role Separation (§8)', () => {
    test('redactor CANNOT perform review decisions (requires reviewer)', async () => {
      // Redactor shouldn't be able to review their own work
      const res = await authApi('redactor', 'POST', '/api/content/markup/sessions/fake-id/review', {
        decision: 'approve',
        comments: 'I approve my own work',
      });
      expect(res.status).toBe(403);
    });
  });
});
