// =============================================================================
// TESSERA — Crypto Core Types
//
// Types for the encryption layer, key management, deconstruction,
// reconstruction, and the positional marker system.
// (Tessera v3.1 §8.3, §8.4, §9, §10)
// =============================================================================

// ── Encryption ─────────────────────────────────────────────────────────

/**
 * Encrypted content set envelope.
 * Each content set is encrypted with AES-256-GCM using a unique key.
 * (Tessera v3.1 §10.1: "At rest: AES-256-GCM; unique key per content set")
 */
export interface EncryptedEnvelope {
  /** Content set identifier (e.g., "A", "B", "C") */
  contentSetIdentifier: string;

  /** AES-256-GCM initialization vector (base64) */
  iv: string;

  /** AES-256-GCM authentication tag (base64) */
  authTag: string;

  /** Encrypted content (base64) */
  ciphertext: string;

  /** SHA-512 hash of the plaintext content before encryption */
  plaintextHash: string;

  /** SHA-512 hash of the ciphertext after encryption */
  ciphertextHash: string;

  /** Key ID referencing the key in the HSM / key store */
  keyId: string;

  /** Algorithm identifier */
  algorithm: 'aes-256-gcm';

  /** Timestamp of encryption */
  encryptedAt: string;
}

/**
 * Decrypted content set — the plaintext result after decryption
 * and integrity verification.
 */
export interface DecryptedContentSet {
  contentSetIdentifier: string;
  plaintext: string;
  verified: boolean;
  verificationHash: string;
}

// ── Key Management ─────────────────────────────────────────────────────

/**
 * Key metadata stored in the database. The actual key material
 * never leaves the HSM. (§10.2: "keys never in plaintext outside HSM")
 */
export interface KeyRecord {
  id: string;
  documentId: string;
  contentSetIdentifier: string;
  organizationId: string;

  /** HSM key handle/label for retrieving the key */
  hsmKeyHandle: string;

  /** Algorithm used */
  algorithm: 'aes-256-gcm';

  /** Shamir share distribution metadata */
  shamirConfig: {
    threshold: number;  // M — minimum shares needed
    totalShares: number; // N — total shares distributed
  };

  /** Whether this key is currently active */
  isActive: boolean;

  /** Previous key ID if this key was created by rotation */
  rotatedFromKeyId: string | null;

  createdAt: string;
  rotatedAt: string | null;
  destroyedAt: string | null;
}

/**
 * A Shamir's Secret Sharing share. (§10.2)
 * Distributed to designated key holders.
 */
export interface ShamirShare {
  /** Share index (1-based) */
  index: number;

  /** The share data (hex-encoded) */
  shareData: string;

  /** Key ID this share belongs to */
  keyId: string;

  /** Designated holder identifier */
  holderId: string;

  /** Whether this share has been distributed */
  distributed: boolean;
}

// ── Positional Markers ─────────────────────────────────────────────────

/**
 * A positional marker placed in the base document where content
 * was extracted. (Tessera v3.1 §8.4)
 *
 * "Each marker: UUID, content set membership, positional metadata,
 *  SHA-512 hash of extracted content."
 *
 * "Markers are opaque — do not reveal type, length, or nature of content."
 *
 * "Adjacent extraction points use single marker to prevent
 *  count-based inference."
 */
export interface PositionalMarker {
  /** Unique marker ID (UUID) */
  markerId: string;

  /** Content set(s) this marker maps to.
   *  Array because content in multiple sets gets one merged marker. */
  contentSetMembership: string[];

  /** Block ID in the intermediate document */
  blockId: string;

  /** Character offset range within the block where content was extracted */
  startOffset: number | null;
  endOffset: number | null;

  /** SHA-512 hash of the extracted content piece */
  contentHash: string;

  /** Whether this marker was merged with adjacent markers */
  isMerged: boolean;

  /** If merged, the original marker IDs that were combined */
  mergedFrom?: string[];

  /** Sequential position within the document for ordering */
  sequencePosition: number;
}

// ── Deconstruction ─────────────────────────────────────────────────────

/**
 * Result of the deconstruction process. (§8.3)
 */
export interface DeconstructionResult {
  documentId: string;

  /** Base document with all redactable content removed;
   *  positional markers at each extraction point. */
  baseDocument: {
    content: string;
    hash: string;
  };

  /** Encrypted content sets stored in separate locations */
  contentSets: EncryptedEnvelope[];

  /** Positional markers mapping base document → content sets */
  markers: PositionalMarker[];

  /** Key records (metadata only — actual keys in HSM) */
  keyRecords: KeyRecord[];

  /** FORAY transaction ID */
  forayTxId: string;

  /** Storage location confirmations */
  storageConfirmations: StorageConfirmation[];

  timestamp: string;
}

/**
 * Storage location confirmation. (§8.3 step 5)
 * "Each encrypted set stored in physically separate location
 *  per organization storage tier."
 */
export interface StorageConfirmation {
  contentSetIdentifier: string;
  storageLocationId: string;
  storageTier: 'tier_1' | 'tier_2' | 'tier_3';
  hash: string;
  confirmedAt: string;
}

// ── Reconstruction ─────────────────────────────────────────────────────

/**
 * Reconstruction request. (§9)
 */
export interface ReconstructionRequest {
  documentId: string;
  viewerId: string;
  accessLevelId: string;
  organizationId: string;
}

/**
 * Reconstructed document view. (§9.1, §9.2)
 */
export interface ReconstructedView {
  documentId: string;
  viewerId: string;
  accessLevelId: string;

  /** The reconstructed document content with redaction markers */
  content: string;

  /** Marker width used for this reconstruction */
  markerWidth: number;

  /** Content sets that were used (for audit) */
  contentSetsUsed: string[];

  /** Content sets that were redacted (viewer lacks access) */
  contentSetsRedacted: string[];

  /** Integrity verification results (§9.2) */
  integrityVerification: {
    baseDocumentVerified: boolean;
    contentSetsVerified: Record<string, boolean>;
    reconstructionHashVerified: boolean;
    allPassed: boolean;
  };

  /** Reconstruction event ID (for watermarking and audit) */
  reconstructionEventId: string;

  timestamp: string;
}
