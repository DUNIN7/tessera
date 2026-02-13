// =============================================================================
// TESSERA — Integration Test Helpers
//
// HTTP client and utilities for testing against a live Tessera server.
// All seed users use password 'tessera-dev-password'.
// =============================================================================

const BASE_URL = process.env.TESSERA_TEST_URL || 'http://localhost:3100';
const PASSWORD = 'tessera-dev-password';

/** Seed user credentials */
export const USERS = {
  sysAdmin:         { email: 'sysadmin@example.com',         role: 'system_admin' },
  orgAdmin:         { email: 'admin@example.com',            role: 'org_admin' },
  redactor:         { email: 'redactor@example.com',         role: 'redactor' },
  reviewer:         { email: 'reviewer@example.com',         role: 'reviewer' },
  viewer:           { email: 'viewer@example.com',           role: 'viewer' },
  auditor:          { email: 'auditor@example.com',          role: 'auditor' },
  aclAuthor:        { email: 'acl-author@example.com',       role: 'acl_author' },
  assetProvisioner: { email: 'asset-provisioner@example.com', role: 'asset_provisioner' },
} as const;

type UserKey = keyof typeof USERS;

/** Token cache to avoid re-logging in for every request */
const tokenCache: Record<string, string> = {};

/** Login and return JWT token. Caches tokens for the test run. */
export async function login(user: UserKey): Promise<string> {
  if (tokenCache[user]) return tokenCache[user];

  const res = await api('POST', '/api/auth/login', {
    email: USERS[user].email,
    password: PASSWORD,
  });

  if (res.status !== 200) {
    const body: any = await res.json();
    throw new Error(`Login failed for ${user}: ${JSON.stringify(body)}`);
  }

  const body: any = await res.json();
  tokenCache[user] = body.token;
  return body.token;
}

/** Clear the token cache (call between test suites if needed) */
export function clearTokenCache(): void {
  Object.keys(tokenCache).forEach(k => delete tokenCache[k]);
}

/**
 * Make an API request to the Tessera server.
 * Returns the raw Response object for flexible assertion.
 */
export async function api(
  method: string,
  path: string,
  body?: any,
  token?: string,
): Promise<Response> {
  const headers: Record<string, string> = {};

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  if (body && !(body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }

  const opts: RequestInit = {
    method,
    headers,
  };

  if (body) {
    opts.body = body instanceof FormData ? body : JSON.stringify(body);
  }

  return fetch(`${BASE_URL}${path}`, opts);
}

/**
 * Authenticated API request — logs in as the given user automatically.
 */
export async function authApi(
  user: UserKey,
  method: string,
  path: string,
  body?: any,
): Promise<Response> {
  const token = await login(user);
  return api(method, path, body, token);
}

/**
 * Parse JSON response with error context.
 */
export async function json(res: Response): Promise<any> {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`Expected JSON but got: ${text.slice(0, 200)}`);
  }
}

/**
 * Assert a response has the expected status code.
 */
export function expectStatus(res: Response, expected: number): void {
  if (res.status !== expected) {
    throw new Error(`Expected status ${expected} but got ${res.status}`);
  }
}

/**
 * Convenience: make request, assert status, return parsed body.
 */
export async function assertApi(
  user: UserKey,
  method: string,
  path: string,
  expectedStatus: number,
  body?: any,
): Promise<any> {
  const res = await authApi(user, method, path, body);
  expect(res.status).toBe(expectedStatus);
  return json(res);
}
