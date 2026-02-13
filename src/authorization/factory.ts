// =============================================================================
// TESSERA — Authorization Provider Factory
//
// Returns the appropriate IAuthorizationProvider based on the organization's
// security profile tier setting. (Parallel Architecture Evaluation §8)
//
// Currently only Tier 1 (Conventional) is implemented.
// Tier 2/3 (Ova) will be added when Kaspa vProgs reach mainnet.
// =============================================================================

import { pool } from '../db/pool';
import { IAuthorizationProvider } from '../types/authorization';
import { ConventionalAuthProvider } from './conventional';

// Singleton instances — providers are stateless, one per tier is sufficient.
const conventionalProvider = new ConventionalAuthProvider();

/**
 * Get the authorization provider for a given organization.
 * Reads the security profile to determine which tier/implementation to use.
 */
export async function getAuthorizationProvider(
  organizationId: string
): Promise<IAuthorizationProvider> {
  const result = await pool.query(
    `SELECT auth_tier FROM security_profiles WHERE organization_id = $1`,
    [organizationId]
  );

  if (result.rows.length === 0) {
    // No security profile = default to Tier 1.
    // This should not happen in production (profile created at org provisioning).
    return conventionalProvider;
  }

  const tier = result.rows[0].auth_tier;

  switch (tier) {
    case 'tier_1':
      return conventionalProvider;

    case 'tier_2':
    case 'tier_3':
      // Future: return new OvaAuthProvider(tier);
      // For now, fall through to conventional with a warning.
      console.warn(
        `[AuthFactory] Organization ${organizationId} configured for ${tier} ` +
        `but Ova provider not yet implemented. Falling back to Tier 1.`
      );
      return conventionalProvider;

    default:
      return conventionalProvider;
  }
}
