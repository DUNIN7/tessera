// =============================================================================
// TESSERA — HSM Key Management
//
// Hardware Security Module interface for key generation, storage,
// and retrieval. (Tessera v3.1 §10.2)
//
// "Key generation: Within HSM; keys never in plaintext outside HSM"
// "HSM access requires multi-party authorization"
//
// Architecture:
//   IHsmProvider — abstract interface for HSM operations
//   SoftHsmProvider — development implementation using in-memory key store
//                     with HKDF-SHA-512 key derivation (§10.1)
//   Pkcs11HsmProvider — production implementation via PKCS#11 (Phase 6)
//
// Development: SoftHSM2 emulation with in-memory secure key store.
// Production: FIPS 140-3 validated HSM via PKCS#11 interface (§15).
//
// "Insider threat control: System admins have no key access." (§10.2)
// Key operations are only accessible through this service; no direct
// database queries can retrieve key material.
// =============================================================================

import { randomBytes, createHash, createHmac } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { splitSecret, reconstructSecret, Share } from './shamir';
import { pool } from '../../db/pool';
import { KeyRecord, ShamirShare } from '../../types/crypto';

// ── HSM Provider Interface ─────────────────────────────────────────────

export interface IHsmProvider {
  /**
   * Generate a new AES-256 key within the HSM.
   * Returns a key handle — the actual key never leaves the HSM.
   */
  generateKey(): Promise<{ keyHandle: string; keyId: string }>;

  /**
   * Retrieve key material for a cryptographic operation.
   * In production HSM, this would perform the operation inside the HSM.
   * In SoftHSM dev mode, it returns the key for local crypto operations.
   */
  getKeyMaterial(keyHandle: string): Promise<Buffer>;

  /**
   * Destroy a key in the HSM. Irreversible. (§12.2 step 5)
   * "Encryption keys destroyed in HSM. Confirmed and recorded."
   */
  destroyKey(keyHandle: string): Promise<boolean>;

  /**
   * Split a key using Shamir's Secret Sharing and store shares.
   * (§10.2: "Shamir's Secret Sharing; M-of-N threshold")
   */
  splitKeyToShares(
    keyHandle: string,
    threshold: number,
    totalShares: number,
    holderIds: string[]
  ): Promise<ShamirShare[]>;

  /**
   * Reconstruct a key from Shamir shares.
   * Used when the primary key handle is unavailable (DR scenario).
   */
  reconstructKeyFromShares(shares: ShamirShare[]): Promise<Buffer>;
}

// ── SoftHSM Development Implementation ─────────────────────────────────

/**
 * In-memory key store for development. Mimics HSM behavior with
 * proper key isolation. Uses HKDF-SHA-512 for key derivation (§10.1).
 *
 * WARNING: This is NOT a production HSM. Keys are stored in memory
 * and will be lost on process restart. Production deployments MUST
 * use a FIPS 140-3 validated HSM via PKCS#11.
 */
class SoftHsmProvider implements IHsmProvider {
  private keyStore = new Map<string, Buffer>();

  async generateKey(): Promise<{ keyHandle: string; keyId: string }> {
    const keyId = uuidv4();
    const keyHandle = `softhsm-${keyId}`;

    // Generate 32 bytes of cryptographically secure random data
    // In production, this happens inside the HSM boundary.
    const keyMaterial = randomBytes(32);

    // Derive the actual encryption key using HKDF-SHA-512 (§10.1)
    // "Key derivation: HKDF-SHA-512 from master secrets"
    const derivedKey = this.hkdfSha512(
      keyMaterial,
      Buffer.from(`tessera-content-set-key-${keyId}`, 'utf-8'),
      Buffer.from('tessera-aes-256-gcm', 'utf-8'),
      32
    );

    this.keyStore.set(keyHandle, derivedKey);

    return { keyHandle, keyId };
  }

  async getKeyMaterial(keyHandle: string): Promise<Buffer> {
    const key = this.keyStore.get(keyHandle);
    if (!key) {
      throw new Error(`Key not found in SoftHSM: ${keyHandle}`);
    }
    // Return a copy to prevent accidental mutation
    return Buffer.from(key);
  }

  async destroyKey(keyHandle: string): Promise<boolean> {
    const existed = this.keyStore.has(keyHandle);
    if (existed) {
      // Overwrite with zeros before deleting (secure erasure)
      const key = this.keyStore.get(keyHandle)!;
      key.fill(0);
      this.keyStore.delete(keyHandle);
    }
    return existed;
  }

  async splitKeyToShares(
    keyHandle: string,
    threshold: number,
    totalShares: number,
    holderIds: string[]
  ): Promise<ShamirShare[]> {
    if (holderIds.length !== totalShares) {
      throw new Error(`Need ${totalShares} holder IDs, got ${holderIds.length}`);
    }

    const keyMaterial = await this.getKeyMaterial(keyHandle);
    const keyId = keyHandle.replace('softhsm-', '');

    // Split using Shamir's Secret Sharing
    const shares = splitSecret(keyMaterial, threshold, totalShares);

    return shares.map((share, i) => ({
      index: share.index,
      shareData: share.data.toString('hex'),
      keyId,
      holderId: holderIds[i],
      distributed: false,
    }));
  }

  async reconstructKeyFromShares(shamirShares: ShamirShare[]): Promise<Buffer> {
    const shares: Share[] = shamirShares.map(s => ({
      index: s.index,
      data: Buffer.from(s.shareData, 'hex'),
    }));

    // Determine key length from first share
    const keyLength = shares[0].data.length;
    return reconstructSecret(shares, keyLength);
  }

  /**
   * HKDF-SHA-512 key derivation. (§10.1)
   * "Key derivation: HKDF-SHA-512 from master secrets"
   */
  private hkdfSha512(
    ikm: Buffer,     // Input key material
    salt: Buffer,    // Salt
    info: Buffer,    // Context/application info
    length: number   // Output key length
  ): Buffer {
    // Extract: PRK = HMAC-SHA-512(salt, IKM)
    const prk = createHmac('sha512', salt).update(ikm).digest();

    // Expand: OKM = T(1) || T(2) || ... truncated to length
    const hashLen = 64; // SHA-512 output length
    const n = Math.ceil(length / hashLen);
    const okm = Buffer.alloc(n * hashLen);

    let prev = Buffer.alloc(0);
    for (let i = 0; i < n; i++) {
      prev = createHmac('sha512', prk)
        .update(Buffer.concat([prev, info, Buffer.from([i + 1])]))
        .digest();
      prev.copy(okm, i * hashLen);
    }

    return okm.subarray(0, length);
  }
}

// ── HSM Provider Factory ───────────────────────────────────────────────

let hsmInstance: IHsmProvider | null = null;

/**
 * Get the HSM provider instance.
 * Phase 3: Always returns SoftHsmProvider.
 * Phase 6: Will check configuration for PKCS#11 HSM.
 */
export function getHsmProvider(): IHsmProvider {
  if (!hsmInstance) {
    // TODO: Phase 6 — check env for PKCS#11 configuration
    // if (process.env.HSM_PKCS11_MODULE) {
    //   hsmInstance = new Pkcs11HsmProvider(process.env.HSM_PKCS11_MODULE);
    // }
    hsmInstance = new SoftHsmProvider();
  }
  return hsmInstance;
}

// ── Key Record Persistence ─────────────────────────────────────────────

/**
 * Save key metadata to the database. (§10.2)
 * Only metadata — actual key material stays in the HSM.
 */
export async function saveKeyRecord(record: KeyRecord, queryClient?: { query: Function }): Promise<void> {
  const db = queryClient || pool;
  await db.query(
    `INSERT INTO encryption_keys
       (id, document_id, content_set_identifier, organization_id,
        hsm_key_handle, algorithm, shamir_threshold, shamir_total_shares,
        is_active, rotated_from_key_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
    [
      record.id, record.documentId, record.contentSetIdentifier,
      record.organizationId, record.hsmKeyHandle, record.algorithm,
      record.shamirConfig.threshold, record.shamirConfig.totalShares,
      record.isActive, record.rotatedFromKeyId,
    ]
  );
}

/**
 * Retrieve key record by document and content set.
 */
export async function getActiveKeyRecord(
  documentId: string,
  contentSetIdentifier: string
): Promise<KeyRecord | null> {
  const result = await pool.query(
    `SELECT * FROM encryption_keys
     WHERE document_id = $1 AND content_set_identifier = $2 AND is_active = true`,
    [documentId, contentSetIdentifier]
  );

  if (result.rows.length === 0) return null;

  const row = result.rows[0];
  return {
    id: row.id,
    documentId: row.document_id,
    contentSetIdentifier: row.content_set_identifier,
    organizationId: row.organization_id,
    hsmKeyHandle: row.hsm_key_handle,
    algorithm: row.algorithm,
    shamirConfig: {
      threshold: row.shamir_threshold,
      totalShares: row.shamir_total_shares,
    },
    isActive: row.is_active,
    rotatedFromKeyId: row.rotated_from_key_id,
    createdAt: row.created_at,
    rotatedAt: row.rotated_at,
    destroyedAt: row.destroyed_at,
  };
}
