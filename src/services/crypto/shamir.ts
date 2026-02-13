// =============================================================================
// TESSERA — Shamir's Secret Sharing
//
// M-of-N threshold secret sharing for encryption key splitting.
// (Tessera v3.1 §10.2)
//
// "Key splitting: Shamir's Secret Sharing; M-of-N threshold per
//  organization security profile"
//
// Implementation over GF(256) — operates on individual bytes,
// producing shares the same length as the secret. Any M shares
// can reconstruct the secret; fewer than M reveal nothing.
//
// This is a pure-TypeScript implementation for the Tessera build.
// Production deployments should validate against known test vectors
// and consider using a FIPS-validated library.
// =============================================================================

import { randomBytes } from 'crypto';

// ── GF(256) Arithmetic ─────────────────────────────────────────────────
// Galois Field 2^8 with irreducible polynomial x^8 + x^4 + x^3 + x + 1
// (0x11B, same as AES)

const EXP_TABLE = new Uint8Array(256);
const LOG_TABLE = new Uint8Array(256);

// Build lookup tables for GF(256) multiplication
(function initTables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP_TABLE[i] = x;
    LOG_TABLE[x] = i;
    x = x << 1;
    if (x & 0x100) x ^= 0x11B;
  }
  EXP_TABLE[255] = EXP_TABLE[0];
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP_TABLE[(LOG_TABLE[a] + LOG_TABLE[b]) % 255];
}

function gfDiv(a: number, b: number): number {
  if (b === 0) throw new Error('Division by zero in GF(256)');
  if (a === 0) return 0;
  return EXP_TABLE[(LOG_TABLE[a] - LOG_TABLE[b] + 255) % 255];
}

function gfAdd(a: number, b: number): number {
  return a ^ b; // Addition in GF(2^8) is XOR
}

// ── Polynomial Evaluation ──────────────────────────────────────────────

/**
 * Evaluate a polynomial at point x in GF(256).
 * coefficients[0] is the constant term (the secret byte).
 */
function evalPoly(coefficients: number[], x: number): number {
  let result = 0;
  for (let i = coefficients.length - 1; i >= 0; i--) {
    result = gfAdd(gfMul(result, x), coefficients[i]);
  }
  return result;
}

// ── Lagrange Interpolation ─────────────────────────────────────────────

/**
 * Recover the secret (constant term) from M points using
 * Lagrange interpolation at x = 0 in GF(256).
 */
function lagrangeInterpolate(
  points: Array<{ x: number; y: number }>
): number {
  let secret = 0;

  for (let i = 0; i < points.length; i++) {
    let numerator = 1;
    let denominator = 1;

    for (let j = 0; j < points.length; j++) {
      if (i === j) continue;
      numerator = gfMul(numerator, points[j].x);            // (0 - x_j) = x_j in GF(2)
      denominator = gfMul(denominator, gfAdd(points[i].x, points[j].x)); // (x_i - x_j)
    }

    const lagrange = gfMul(points[i].y, gfDiv(numerator, denominator));
    secret = gfAdd(secret, lagrange);
  }

  return secret;
}

// ── Public API ─────────────────────────────────────────────────────────

export interface Share {
  /** Share index (1-based, used as x-coordinate in polynomial) */
  index: number;

  /** Share data — same length as the secret */
  data: Buffer;
}

/**
 * Split a secret into N shares with threshold M. (§10.2)
 * Any M shares can reconstruct the secret. M-1 shares reveal nothing.
 *
 * @param secret — the secret to split (Buffer)
 * @param threshold — M: minimum shares needed to reconstruct
 * @param totalShares — N: total number of shares to generate
 * @returns Array of N shares
 */
export function splitSecret(
  secret: Buffer,
  threshold: number,
  totalShares: number
): Share[] {
  if (threshold < 2) throw new Error('Threshold must be at least 2');
  if (totalShares < threshold) throw new Error('Total shares must be >= threshold');
  if (totalShares > 254) throw new Error('Maximum 254 shares (GF(256) constraint)');
  if (secret.length === 0) throw new Error('Secret cannot be empty');

  const shares: Share[] = [];

  // Initialize share buffers
  for (let i = 0; i < totalShares; i++) {
    shares.push({
      index: i + 1,  // x-coordinates: 1, 2, ..., N (never 0, as 0 is the secret)
      data: Buffer.alloc(secret.length),
    });
  }

  // For each byte of the secret, construct a random polynomial
  // of degree (threshold - 1) with the secret byte as constant term,
  // then evaluate at each share's x-coordinate.
  for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
    // Build polynomial: coefficients[0] = secret byte, rest random
    const coefficients: number[] = [secret[byteIdx]];
    const randomCoeffs = randomBytes(threshold - 1);
    for (let k = 0; k < threshold - 1; k++) {
      coefficients.push(randomCoeffs[k]);
    }

    // Evaluate polynomial at each share's x-coordinate
    for (let shareIdx = 0; shareIdx < totalShares; shareIdx++) {
      shares[shareIdx].data[byteIdx] = evalPoly(coefficients, shareIdx + 1);
    }
  }

  return shares;
}

/**
 * Reconstruct a secret from M or more shares. (§10.2)
 *
 * @param shares — at least M shares (threshold shares)
 * @param secretLength — expected length of the secret
 * @returns Reconstructed secret
 */
export function reconstructSecret(
  shares: Share[],
  secretLength: number
): Buffer {
  if (shares.length < 2) throw new Error('Need at least 2 shares to reconstruct');

  // Verify all shares have correct length
  for (const share of shares) {
    if (share.data.length !== secretLength) {
      throw new Error(
        `Share ${share.index} has length ${share.data.length}, expected ${secretLength}`
      );
    }
  }

  // Check for duplicate indices
  const indices = new Set(shares.map(s => s.index));
  if (indices.size !== shares.length) {
    throw new Error('Duplicate share indices detected');
  }

  const secret = Buffer.alloc(secretLength);

  // For each byte position, perform Lagrange interpolation
  for (let byteIdx = 0; byteIdx < secretLength; byteIdx++) {
    const points = shares.map(share => ({
      x: share.index,
      y: share.data[byteIdx],
    }));

    secret[byteIdx] = lagrangeInterpolate(points);
  }

  return secret;
}

/**
 * Verify that a set of shares can reconstruct a known secret.
 * Used for share verification without exposing the secret.
 */
export function verifyShares(
  shares: Share[],
  expectedHash: string,
  secretLength: number
): boolean {
  try {
    const { createHash } = require('crypto');
    const reconstructed = reconstructSecret(shares, secretLength);
    const hash = createHash('sha512').update(reconstructed).digest('hex');
    return hash === expectedHash;
  } catch {
    return false;
  }
}
