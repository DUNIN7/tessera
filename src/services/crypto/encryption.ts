// =============================================================================
// TESSERA — AES-256-GCM Encryption Service
//
// Content set encryption and decryption using AES-256-GCM.
// (Tessera v3.1 §10.1)
//
// "At rest: AES-256-GCM; unique key per content set"
// "Hashing: SHA-512 for all integrity verification"
//
// Keys are generated and managed through the HSM interface (hsm.ts).
// This module performs the actual encrypt/decrypt operations using
// key material retrieved from the HSM.
//
// Quantum resistance note (§10.1): "Architecture supports algorithm
// migration to NIST post-quantum standards via key wrapping and
// re-encryption without re-deconstruction." The EncryptedEnvelope
// includes an algorithm field to support future migration.
// =============================================================================

import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'crypto';
import { EncryptedEnvelope, DecryptedContentSet } from '../../types/crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;          // GCM recommended IV length
const AUTH_TAG_LENGTH = 16;    // 128-bit authentication tag

/**
 * Compute SHA-512 hash of data. (§10.1)
 * Used throughout for integrity verification.
 */
export function sha512(data: string | Buffer): string {
  return createHash('sha512')
    .update(typeof data === 'string' ? Buffer.from(data, 'utf-8') : data)
    .digest('hex');
}

/**
 * Encrypt a content set's plaintext using AES-256-GCM. (§10.1)
 *
 * @param plaintext — the content set data to encrypt
 * @param key — 32-byte AES-256 key (from HSM)
 * @param keyId — key identifier for the envelope
 * @param contentSetIdentifier — which content set this is
 * @returns EncryptedEnvelope with ciphertext, IV, auth tag, and hashes
 */
export function encryptContentSet(
  plaintext: string,
  key: Buffer,
  keyId: string,
  contentSetIdentifier: string
): EncryptedEnvelope {
  if (key.length !== 32) {
    throw new Error('AES-256 requires a 32-byte key');
  }

  // Generate random IV for each encryption operation
  const iv = randomBytes(IV_LENGTH);

  // Compute plaintext hash before encryption (for integrity verification)
  const plaintextHash = sha512(plaintext);

  // Encrypt
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });

  // Use content set identifier as additional authenticated data (AAD)
  // This binds the ciphertext to its intended content set, preventing
  // ciphertext from being substituted between sets.
  cipher.setAAD(Buffer.from(contentSetIdentifier, 'utf-8'));

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf-8'),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  // Compute ciphertext hash (for storage verification)
  const ciphertextHash = sha512(encrypted);

  return {
    contentSetIdentifier,
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: encrypted.toString('base64'),
    plaintextHash,
    ciphertextHash,
    keyId,
    algorithm: ALGORITHM,
    encryptedAt: new Date().toISOString(),
  };
}

/**
 * Decrypt an encrypted content set envelope. (§10.1)
 * Verifies integrity at every step:
 *   1. Ciphertext hash matches stored hash
 *   2. GCM authentication tag validates (tamper detection)
 *   3. Decrypted plaintext hash matches stored hash
 *
 * @param envelope — the encrypted content set
 * @param key — 32-byte AES-256 key (from HSM)
 * @returns DecryptedContentSet with plaintext and verification status
 * @throws on authentication failure (tampered ciphertext)
 */
export function decryptContentSet(
  envelope: EncryptedEnvelope,
  key: Buffer
): DecryptedContentSet {
  if (key.length !== 32) {
    throw new Error('AES-256 requires a 32-byte key');
  }

  const iv = Buffer.from(envelope.iv, 'base64');
  const authTag = Buffer.from(envelope.authTag, 'base64');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');

  // Step 1: Verify ciphertext hash
  const computedCiphertextHash = sha512(ciphertext);
  if (computedCiphertextHash !== envelope.ciphertextHash) {
    throw new Error(
      `Ciphertext integrity failure for content set "${envelope.contentSetIdentifier}": ` +
      `hash mismatch. Content may have been tampered with.`
    );
  }

  // Step 2: Decrypt with GCM authentication
  const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);
  decipher.setAAD(Buffer.from(envelope.contentSetIdentifier, 'utf-8'));

  let plaintext: string;
  try {
    plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]).toString('utf-8');
  } catch (err: any) {
    throw new Error(
      `GCM authentication failure for content set "${envelope.contentSetIdentifier}": ` +
      `ciphertext or authentication tag has been tampered with.`
    );
  }

  // Step 3: Verify plaintext hash
  const computedPlaintextHash = sha512(plaintext);
  const verified = computedPlaintextHash === envelope.plaintextHash;

  if (!verified) {
    throw new Error(
      `Plaintext integrity failure for content set "${envelope.contentSetIdentifier}": ` +
      `decrypted content hash does not match original.`
    );
  }

  return {
    contentSetIdentifier: envelope.contentSetIdentifier,
    plaintext,
    verified,
    verificationHash: computedPlaintextHash,
  };
}

/**
 * Re-encrypt a content set with a new key (for key rotation).
 * (§10.2: "Key rotation: re-encrypts without re-deconstruction")
 *
 * Decrypts with old key, re-encrypts with new key.
 * Returns new envelope with updated key reference.
 */
export function reEncryptContentSet(
  envelope: EncryptedEnvelope,
  oldKey: Buffer,
  newKey: Buffer,
  newKeyId: string
): EncryptedEnvelope {
  // Decrypt with old key
  const decrypted = decryptContentSet(envelope, oldKey);

  // Re-encrypt with new key
  return encryptContentSet(
    decrypted.plaintext,
    newKey,
    newKeyId,
    envelope.contentSetIdentifier
  );
}
