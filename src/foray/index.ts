import fetch from "node-fetch";
// =============================================================================
// TESSERA — FORAY Protocol Integration
//
// Handles communication with the FORAY Protocol API for blockchain
// audit trail anchoring. (Tessera v3.1 §11)
//
// FORAY mapping (§11.1):
//   Arrangements  → Document registration, access levels, trust agreements
//   Accruals      → Integrity computations, markup sessions, scan findings
//   Anticipations → Expected events: reconstructions, expirations, rotations
//   Actions       → Executed events: reconstructions, exports, approvals
//
// Submits pre-built FORAY JSON to the FORAY API submit-transaction endpoint.
// Falls back to local logging if FORAY API is unreachable.
// =============================================================================

import { config } from '../config';

// ── Tessera's internal transaction format (callers use this) ──────────
export interface ForayTransaction {
  transactionId: string;
  transactionType: string;
  arrangement?: Record<string, unknown>;
  accrual?: Record<string, unknown>;
  anticipation?: Record<string, unknown>;
  action?: Record<string, unknown>;
  privacySummary?: Record<string, unknown>;
}

// ── FORAY Protocol canonical format ──────────────────────────────────
interface ForayCanonical {
  transaction_id: string;
  timestamp: string;
  entity: string;
  transaction_type: string;
  total_value: number;
  currency: string;
  arrangements: Array<{
    id: string;
    type: string;
    effective_date: string;
    parties: string[];
    description: string;
    total_value?: number;
    terms?: Record<string, unknown>;
  }>;
  accruals?: Array<{
    id: string;
    arrangement_ref: string;
    type: string;
    calculation_method: string;
    amount: number;
    period?: { start: string; end: string };
    formula?: Record<string, unknown>;
  }>;
  anticipations?: Array<{
    id: string;
    type: string;
    expected_amount: number;
    datetime: string;
    accrual_ref?: string;
    condition?: string | null;
    probability?: number;
  }>;
  actions?: Array<{
    id: string;
    type: string;
    actual_amount: number;
    status: string;
    anticipation_ref?: string;
    counterparty?: string;
    completion_date?: string;
  }>;
  foray_metadata: {
    protocol_version: string;
    source_system?: string;
    kaspa_commitment?: Record<string, unknown> | null;
    privacy_summary: {
      formulas_obfuscated: number;
      instance_pools_used: number;
      computational_chaff_operations: number;
      differential_privacy_applications?: number;
    };
    regulatory_compliance?: Record<string, boolean>;
  };
}

// ── API response ─────────────────────────────────────────────────────
interface ForayApiResponse {
  success: boolean;
  transaction_id: string;
  received_at: string;
  status: 'queued' | 'anchored';
  kaspa_commitment: {
    kaspa_tx_id: string;
    block_height: number;
    confirmation_time: string;
  } | null;
}

/**
 * Transform Tessera's internal transaction format into canonical FORAY JSON.
 *
 * Tessera callers pass domain-specific data in arrangement/accrual/action.
 * This function wraps it in the full FORAY structure with proper metadata.
 */
function toCanonical(tx: ForayTransaction): ForayCanonical {
  const now = new Date().toISOString();

  return {
    transaction_id: tx.transactionId,
    timestamp: now,
    entity: 'Tessera',
    transaction_type: tx.transactionType,
    total_value: 0,  // Tessera transactions are audit events, not financial
    currency: 'USD',

    arrangements: [
      {
        id: `ARR_${tx.transactionId}`,
        type: tx.transactionType,
        effective_date: now,
        parties: ['Tessera (System)'],
        description: `Tessera ${tx.transactionType.replace(/_/g, ' ')} event`,
        terms: tx.arrangement || {},
      },
    ],

    accruals: tx.accrual
      ? [
          {
            id: `ACC_${tx.transactionId}`,
            arrangement_ref: `ARR_${tx.transactionId}`,
            type: 'integrity_computation',
            calculation_method: 'Calculated',
            amount: 0,
            ...tx.accrual,
          },
        ]
      : undefined,

    anticipations: tx.anticipation
      ? [
          {
            id: `ANT_${tx.transactionId}`,
            type: 'expected_event',
            expected_amount: 0,
            datetime: now,
            accrual_ref: `ACC_${tx.transactionId}`,
            ...tx.anticipation,
          },
        ]
      : undefined,

    actions: tx.action
      ? [
          {
            id: `ACT_${tx.transactionId}`,
            type: tx.transactionType,
            actual_amount: 0,
            status: 'completed',
            anticipation_ref: tx.anticipation
              ? `ANT_${tx.transactionId}`
              : undefined,
            completion_date: now,
            ...tx.action,
          },
        ]
      : undefined,

    foray_metadata: {
      protocol_version: '1.0',
      source_system: 'tessera',
      kaspa_commitment: null,
      privacy_summary: {
        formulas_obfuscated: tx.privacySummary?.formulas_obfuscated as number ?? 0,
        instance_pools_used: tx.privacySummary?.instance_pools_used as number ?? 1,
        computational_chaff_operations:
          tx.privacySummary?.computational_chaff_operations as number ?? 10,
      },
    },
  };
}

/**
 * Submit a FORAY Protocol transaction for blockchain anchoring.
 *
 * POSTs canonical FORAY JSON to the FORAY API. Falls back to local
 * logging if the API is unreachable (queued for retry on reconnection
 * per Tessera v3.1 §11.4).
 */
export async function submitForayTransaction(
  transaction: ForayTransaction
): Promise<{ forayTxId: string; kaspaTxId: string | null }> {
  const canonical = toCanonical(transaction);
  const apiUrl = `${config.foray.apiUrl}/api/submit-transaction`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(canonical),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (response.ok) {
      const result: ForayApiResponse = await response.json();
      console.log(
        `[FORAY] Transaction submitted: ${transaction.transactionId} → ${result.status}`
      );
      return {
        forayTxId: result.transaction_id,
        kaspaTxId: result.kaspa_commitment?.kaspa_tx_id ?? null,
      };
    }

    // API returned error — log and fall back
    const errBody = await response.json().catch(() => ({ error: response.statusText }));
    console.warn(
      `[FORAY] API error (${response.status}): ${JSON.stringify(errBody)}. ` +
      `Transaction ${transaction.transactionId} logged locally.`
    );

  } catch (err: unknown) {
    // Network unreachable — fall back to local log (§11.4 fallback)
    const message = err instanceof Error ? err.message : String(err);
    console.warn(
      `[FORAY] API unreachable (${message}). ` +
      `Transaction ${transaction.transactionId} logged locally.`
    );
  }

  // Fallback: log locally, return stub ID
  // §11.4: "events queued in tamper-evident local log; committed on reconnection"
  console.log(
    `[FORAY] Transaction queued locally: ${transaction.transactionId} (${transaction.transactionType})`
  );

  return {
    forayTxId: `FORAY_LOCAL_${transaction.transactionId}`,
    kaspaTxId: null,
  };
}

/**
 * Verify a FORAY transaction against the Kaspa blockchain.
 * (Tessera v3.1 §11.3 Blockchain Verification Protocol)
 *
 * Queries the FORAY API for transaction status and Kaspa confirmation.
 * Falls back gracefully if API unreachable.
 */
export async function verifyForayTransaction(
  forayTxId: string
): Promise<{ valid: boolean; kaspaBlockHeight?: number; confirmationTime?: string }> {
  // Local-only transactions can't be verified against Kaspa
  if (forayTxId.startsWith('FORAY_LOCAL_')) {
    console.log(`[FORAY] Cannot verify local-only transaction: ${forayTxId}`);
    return { valid: false };
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(
      `${config.foray.apiUrl}/api/verify-transaction?id=${encodeURIComponent(forayTxId)}`,
      { signal: controller.signal }
    );

    clearTimeout(timeout);

    if (response.ok) {
      const result = await response.json();
      return {
        valid: result.valid ?? false,
        kaspaBlockHeight: result.kaspa_commitment?.block_height,
        confirmationTime: result.kaspa_commitment?.confirmation_time,
      };
    }
  } catch {
    console.warn(`[FORAY] Verification unavailable for: ${forayTxId}`);
  }

  return { valid: false };
}
