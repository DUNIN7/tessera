// =============================================================================
// TESSERA — Conventional Authorization Provider (Tier 1)
//
// Server-mediated RBAC using the user_access_grants table.
// This is the default authorization mechanism for Tier 1 deployments.
// 
// Parallel Architecture Evaluation §8:
// "Application-layer access level checking; standard RBAC.
//  Kaspa dependency: Audit trail only (FORAY)."
// =============================================================================

import { pool } from '../db/pool';
import {
  IAuthorizationProvider,
  AuthorizationRequest,
  AuthorizationResult,
  ContentSetRef,
} from '../types/authorization';

export class ConventionalAuthProvider implements IAuthorizationProvider {
  readonly name = 'Conventional RBAC (Tier 1)';
  readonly tier = 'tier_1' as const;

  async authorize(request: AuthorizationRequest): Promise<AuthorizationResult> {
    const now = new Date();

    // Check for an active, non-expired, non-revoked grant
    const grantResult = await pool.query(
      `SELECT g.id, g.expires_at
       FROM user_access_grants g
       JOIN access_levels al ON al.id = g.access_level_id
       WHERE g.user_id = $1
         AND g.document_id = $2
         AND g.access_level_id = $3
         AND g.is_revoked = false
         AND al.is_active = true
         AND al.organization_id = $4
       LIMIT 1`,
      [request.userId, request.documentId, request.accessLevelId, request.organizationId]
    );

    if (grantResult.rows.length === 0) {
      return this.denied('no_grant', now);
    }

    const grant = grantResult.rows[0];

    // Check time-bound expiration (Tessera v3.1 §5.4)
    if (grant.expires_at && new Date(grant.expires_at) < now) {
      return this.denied('expired', now);
    }

    // Grant exists and is valid — resolve content set references
    const contentSets = await pool.query(
      `SELECT cs.id, cs.set_identifier, cs.storage_ref, cs.encrypted_hash
       FROM content_sets cs
       JOIN access_level_content_sets alcs ON alcs.content_set_id = cs.id
       WHERE alcs.access_level_id = $1
         AND cs.is_destroyed = false
         AND cs.organization_id = $2`,
      [request.accessLevelId, request.organizationId]
    );

    const contentSetRefs: ContentSetRef[] = contentSets.rows.map((row: any) => ({
      contentSetId: row.id,
      setIdentifier: row.set_identifier,
      storageRef: row.storage_ref || '',
      encryptedHash: row.encrypted_hash || '',
    }));

    return {
      granted: true,
      contentSetRefs,
      provider: 'conventional',
      auditMetadata: {
        method: 'database_grant_lookup',
        decidedAt: now,
        providerData: { grantId: grant.id },
      },
    };
  }

  async isAvailable(): Promise<boolean> {
    try {
      await pool.query('SELECT 1');
      return true;
    } catch {
      return false;
    }
  }

  async revokeAccess(
    userId: string,
    documentId: string,
    accessLevelId: string
  ): Promise<void> {
    await pool.query(
      `UPDATE user_access_grants
       SET is_revoked = true, revoked_at = now()
       WHERE user_id = $1 AND document_id = $2 AND access_level_id = $3
         AND is_revoked = false`,
      [userId, documentId, accessLevelId]
    );
  }

  private denied(
    reason: AuthorizationResult['denialReason'],
    now: Date
  ): AuthorizationResult {
    return {
      granted: false,
      contentSetRefs: [],
      provider: 'conventional',
      denialReason: reason,
      auditMetadata: {
        method: 'database_grant_lookup',
        decidedAt: now,
      },
    };
  }
}
