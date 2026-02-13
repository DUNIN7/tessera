// =============================================================================
// TESSERA — Test Suite 01: Health & Connectivity
// =============================================================================

import { api, json } from './helpers';

describe('Health & Connectivity', () => {
  test('GET /api/health returns healthy status', async () => {
    const res = await api('GET', '/api/health');
    expect(res.status).toBe(200);

    const body = await json(res);
    expect(body.status).toBe('healthy');
    expect(body.service).toBe('tessera');
    expect(body.version).toBe('0.6.0');
    expect(body.checks.database.status).toBe('healthy');
    expect(body.checks.hsm.status).toBe('healthy');
    expect(typeof body.checks.database.latencyMs).toBe('number');
  });

  test('Unknown route returns 404', async () => {
    const res = await api('GET', '/api/nonexistent');
    expect(res.status).toBe(404);
  });

  test('Protected route without token returns 401', async () => {
    const res = await api('GET', '/api/content/documents');
    expect(res.status).toBe(401);
  });
});
