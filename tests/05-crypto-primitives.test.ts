// =============================================================================
// TESSERA — Test Suite 05: Crypto Primitives
//
// Unit-level tests for the crypto core, run as part of the integration suite.
// These verify the fundamental security guarantees:
//   - AES-256-GCM encryption/decryption works correctly
//   - SHA-512 integrity hashing is consistent
//   - Tamper detection catches modifications
//   - Key rotation preserves content
//   - AAD binding prevents content set substitution
//
// (Tessera v3.1 §10.1)
// =============================================================================

import { randomBytes } from 'crypto';

// Import crypto functions directly for unit testing
// These paths work when running from the project root
let encryptContentSet: any;
let decryptContentSet: any;
let reEncryptContentSet: any;
let sha512: any;

beforeAll(async () => {
  // Dynamic import to handle tsx module resolution
  const encryption = await import('../src/services/crypto/encryption');
  encryptContentSet = encryption.encryptContentSet;
  decryptContentSet = encryption.decryptContentSet;
  reEncryptContentSet = encryption.reEncryptContentSet;
  sha512 = encryption.sha512;
});

describe('SHA-512 Hashing', () => {
  test('produces consistent 128-char hex output', () => {
    const hash = sha512('hello world');
    expect(hash).toHaveLength(128); // SHA-512 = 64 bytes = 128 hex chars
    expect(hash).toMatch(/^[0-9a-f]+$/);
  });

  test('same input produces same hash', () => {
    const hash1 = sha512('deterministic');
    const hash2 = sha512('deterministic');
    expect(hash1).toBe(hash2);
  });

  test('different input produces different hash', () => {
    const hash1 = sha512('input-a');
    const hash2 = sha512('input-b');
    expect(hash1).not.toBe(hash2);
  });

  test('handles Buffer input', () => {
    const hash = sha512(Buffer.from('buffer data'));
    expect(hash).toHaveLength(128);
  });

  test('empty string produces valid hash', () => {
    const hash = sha512('');
    expect(hash).toHaveLength(128);
  });
});

describe('AES-256-GCM Encryption', () => {
  const key = randomBytes(32);
  const keyId = 'test-key-001';
  const contentSetId = 'CS-TEST';
  const plaintext = 'This is classified content that must be protected at rest.';

  test('encrypt returns valid envelope structure', () => {
    const envelope = encryptContentSet(plaintext, key, keyId, contentSetId);

    expect(envelope.contentSetIdentifier).toBe(contentSetId);
    expect(envelope.keyId).toBe(keyId);
    expect(envelope.algorithm).toBe('aes-256-gcm');
    expect(envelope.iv).toBeDefined();
    expect(envelope.authTag).toBeDefined();
    expect(envelope.ciphertext).toBeDefined();
    expect(envelope.plaintextHash).toBeDefined();
    expect(envelope.ciphertextHash).toBeDefined();
    expect(envelope.encryptedAt).toBeDefined();

    // Ciphertext should be base64
    expect(() => Buffer.from(envelope.ciphertext, 'base64')).not.toThrow();

    // Hashes should be SHA-512 (128 hex chars)
    expect(envelope.plaintextHash).toHaveLength(128);
    expect(envelope.ciphertextHash).toHaveLength(128);
  });

  test('ciphertext differs from plaintext', () => {
    const envelope = encryptContentSet(plaintext, key, keyId, contentSetId);
    const ciphertextBuf = Buffer.from(envelope.ciphertext, 'base64');
    expect(ciphertextBuf.toString('utf-8')).not.toBe(plaintext);
  });

  test('same plaintext with same key produces different ciphertext (random IV)', () => {
    const env1 = encryptContentSet(plaintext, key, keyId, contentSetId);
    const env2 = encryptContentSet(plaintext, key, keyId, contentSetId);
    expect(env1.ciphertext).not.toBe(env2.ciphertext);
    expect(env1.iv).not.toBe(env2.iv);
  });

  test('rejects key shorter than 32 bytes', () => {
    expect(() => {
      encryptContentSet(plaintext, Buffer.alloc(16), keyId, contentSetId);
    }).toThrow('32-byte key');
  });
});

describe('AES-256-GCM Decryption', () => {
  const key = randomBytes(32);
  const plaintext = 'Sensitive personnel records and clearance levels for Project AURORA.';

  test('decrypt recovers original plaintext', () => {
    const envelope = encryptContentSet(plaintext, key, 'k1', 'CS-A');
    const result = decryptContentSet(envelope, key);

    expect(result.plaintext).toBe(plaintext);
    expect(result.verified).toBe(true);
    expect(result.contentSetIdentifier).toBe('CS-A');
  });

  test('wrong key fails GCM authentication', () => {
    const envelope = encryptContentSet(plaintext, key, 'k1', 'CS-A');
    const wrongKey = randomBytes(32);

    expect(() => {
      decryptContentSet(envelope, wrongKey);
    }).toThrow(/authentication failure|tampered/i);
  });

  test('tampered ciphertext detected by hash check', () => {
    const envelope = encryptContentSet(plaintext, key, 'k1', 'CS-A');

    // Tamper with ciphertext
    const tamperedEnvelope = { ...envelope };
    const buf = Buffer.from(tamperedEnvelope.ciphertext, 'base64');
    buf[0] ^= 0xFF; // Flip bits
    tamperedEnvelope.ciphertext = buf.toString('base64');

    expect(() => {
      decryptContentSet(tamperedEnvelope, key);
    }).toThrow(/integrity failure|tampered/i);
  });

  test('tampered auth tag detected by GCM', () => {
    const envelope = encryptContentSet(plaintext, key, 'k1', 'CS-A');

    // Tamper with auth tag
    const tamperedEnvelope = { ...envelope };
    const tagBuf = Buffer.from(tamperedEnvelope.authTag, 'base64');
    tagBuf[0] ^= 0xFF;
    tamperedEnvelope.authTag = tagBuf.toString('base64');
    // Also fix the ciphertext hash so it passes the first check
    tamperedEnvelope.ciphertextHash = envelope.ciphertextHash;

    expect(() => {
      decryptContentSet(tamperedEnvelope, key);
    }).toThrow(/authentication failure|tampered/i);
  });

  test('wrong content set identifier fails AAD verification', () => {
    const envelope = encryptContentSet(plaintext, key, 'k1', 'CS-ORIGINAL');

    // Try to decrypt with wrong content set ID (AAD mismatch)
    const swappedEnvelope = { ...envelope, contentSetIdentifier: 'CS-SWAPPED' };

    expect(() => {
      decryptContentSet(swappedEnvelope, key);
    }).toThrow(/authentication failure|tampered/i);
  });
});

describe('Key Rotation (§10.2)', () => {
  test('re-encryption with new key preserves plaintext', () => {
    const oldKey = randomBytes(32);
    const newKey = randomBytes(32);
    const plaintext = 'Content that survives key rotation without re-deconstruction.';

    const originalEnvelope = encryptContentSet(plaintext, oldKey, 'old-key', 'CS-ROTATE');
    const rotatedEnvelope = reEncryptContentSet(originalEnvelope, oldKey, newKey, 'new-key');

    // New envelope should have different ciphertext
    expect(rotatedEnvelope.ciphertext).not.toBe(originalEnvelope.ciphertext);
    expect(rotatedEnvelope.keyId).toBe('new-key');

    // Decrypt with new key should recover original
    const result = decryptContentSet(rotatedEnvelope, newKey);
    expect(result.plaintext).toBe(plaintext);
    expect(result.verified).toBe(true);

    // Old key should NOT work on rotated envelope
    expect(() => {
      decryptContentSet(rotatedEnvelope, oldKey);
    }).toThrow();
  });

  test('plaintext hash remains consistent through rotation', () => {
    const oldKey = randomBytes(32);
    const newKey = randomBytes(32);
    const plaintext = 'Hash consistency test.';

    const original = encryptContentSet(plaintext, oldKey, 'k1', 'CS-X');
    const rotated = reEncryptContentSet(original, oldKey, newKey, 'k2');

    // Plaintext hash should be identical (same content, different encryption)
    expect(rotated.plaintextHash).toBe(original.plaintextHash);
  });
});

describe('Edge Cases', () => {
  test('encrypts empty string', () => {
    const key = randomBytes(32);
    const envelope = encryptContentSet('', key, 'k1', 'CS-EMPTY');
    const result = decryptContentSet(envelope, key);
    expect(result.plaintext).toBe('');
    expect(result.verified).toBe(true);
  });

  test('encrypts large content (1MB)', () => {
    const key = randomBytes(32);
    const largeContent = 'X'.repeat(1024 * 1024);
    const envelope = encryptContentSet(largeContent, key, 'k1', 'CS-LARGE');
    const result = decryptContentSet(envelope, key);
    expect(result.plaintext).toBe(largeContent);
    expect(result.verified).toBe(true);
  });

  test('encrypts unicode content', () => {
    const key = randomBytes(32);
    const unicode = '日本語テスト — classified 机密 — ████████ redacted';
    const envelope = encryptContentSet(unicode, key, 'k1', 'CS-UNICODE');
    const result = decryptContentSet(envelope, key);
    expect(result.plaintext).toBe(unicode);
    expect(result.verified).toBe(true);
  });

  test('encrypts content with special characters', () => {
    const key = randomBytes(32);
    const special = '<script>alert("xss")</script>\n\r\t\0\x00\xFF';
    const envelope = encryptContentSet(special, key, 'k1', 'CS-SPECIAL');
    const result = decryptContentSet(envelope, key);
    expect(result.plaintext).toBe(special);
  });
});
