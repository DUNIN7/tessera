// =============================================================================
// TESSERA — Authorization Provider Interface
//
// This is the core abstraction from Parallel Architecture Evaluation §8:
// "The Tessera application defines a clean interface boundary (an
// authorization provider abstraction) that supports either a conventional
// access control backend or the Ova composed-proof backend. The interface
// accepts an authorization request (viewer credential, document ID,
// requested access level) and returns an authorization result (approved
// with content set key references, or denied). The Ova implementation
// submits composed proofs to the blockDAG; the conventional implementation
// checks an internal access list. Both return the same result type to
// the reconstruction engine."
//
// Implementations:
//   Tier 1: ConventionalAuthProvider — server-mediated RBAC
//   Tier 2: OvaAuthProvider (future) — Ova with cached fallback
//   Tier 3: OvaAuthProvider (future) — Ova with hard dependency
// =============================================================================

/**
 * Request to authorize a reconstruction or access operation.
 */
export interface AuthorizationRequest {
  /** ID of the user requesting access */
  userId: string;
  
  /** ID of the document being accessed */
  documentId: string;
  
  /** ID of the access level being requested */
  accessLevelId: string;
  
  /** Organization ID (tenant scope) */
  organizationId: string;
  
  /** Type of access being requested */
  accessType: 'reconstruct' | 'export';
}

/**
 * Result of an authorization decision.
 * 
 * In Tier 1, contentSetRefs are database-resolved storage references.
 * In Tier 2/3, they would be decryption key references obtained from
 * Ova Asset Egg payloads after successful ZK proof verification.
 */
export interface AuthorizationResult {
  /** Whether access is granted */
  granted: boolean;
  
  /** Content set references the user may access (empty if denied) */
  contentSetRefs: ContentSetRef[];
  
  /** Which authorization provider made the decision */
  provider: 'conventional' | 'ova' | 'ova_cached';
  
  /** Reason for denial (if denied). Machine-readable code. */
  denialReason?: 'no_grant' | 'expired' | 'revoked' | 'level_inactive' | 'proof_failed' | 'blockchain_unavailable';
  
  /** FORAY audit metadata for this decision */
  auditMetadata: {
    /** How the decision was made */
    method: string;
    /** Timestamp of the decision */
    decidedAt: Date;
    /** Additional provider-specific audit data */
    providerData?: Record<string, unknown>;
  };
}

/**
 * Reference to an accessible content set, returned on successful authorization.
 */
export interface ContentSetRef {
  /** Content set ID */
  contentSetId: string;
  
  /** Content set identifier (e.g., "A", "B") */
  setIdentifier: string;
  
  /**
   * Storage reference for retrieving the encrypted content.
   * In Tier 1: path or object store key from the database.
   * In Tier 2/3: reference obtained from Ova Asset Egg payload.
   */
  storageRef: string;
  
  /** SHA-512 hash for integrity verification (Tessera v3.1 §9.2) */
  encryptedHash: string;
}

/**
 * The authorization provider interface.
 * 
 * Each organization's security profile determines which implementation
 * is used. The reconstruction engine calls this interface without
 * knowledge of the underlying authorization mechanism.
 */
export interface IAuthorizationProvider {
  /** Human-readable name of this provider (for logging/audit) */
  readonly name: string;
  
  /** Which tier this provider implements */
  readonly tier: 'tier_1' | 'tier_2' | 'tier_3';
  
  /**
   * Authorize an access request.
   * 
   * Tier 1: Checks user_access_grants table.
   * Tier 2 (future): Submits Ova composed proof; falls back to cached
   *   authorization if Kaspa unavailable.
   * Tier 3 (future): Submits Ova composed proof; fails hard if
   *   Kaspa unavailable.
   */
  authorize(request: AuthorizationRequest): Promise<AuthorizationResult>;
  
  /**
   * Check if this provider is currently available/healthy.
   * Tier 1: Always true (database-backed).
   * Tier 2/3: Depends on Kaspa blockchain availability.
   */
  isAvailable(): Promise<boolean>;
  
  /**
   * Revoke a user's access to a document at a specific level.
   * 
   * Tier 1: Marks grant as revoked in database.
   * Tier 2/3 (future): Updates ACL/Group Egg roster, triggering
   *   state root change and invalidating existing proofs.
   */
  revokeAccess(userId: string, documentId: string, accessLevelId: string): Promise<void>;
}
