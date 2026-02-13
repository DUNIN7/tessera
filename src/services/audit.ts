// =============================================================================
// TESSERA — Audit Service
//
// Append-only audit trail. (Tessera v3.1 §11)
// Every auditable event recorded locally AND queued for FORAY/Kaspa anchoring.
//
// Events are categorized by FORAY 4A component:
//   arrangement:  registrations, config changes, access level CRUD
//   accrual:      integrity computations, markup sessions, scan findings
//   anticipation: expected future events (expirations, rotations)
//   action:       executed events (reconstructions, exports, approvals)
// =============================================================================

import { pool } from '../db/pool';
import { createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { UserRole, RoleLayer } from '../types/roles';

type AuditCategory = 'arrangement' | 'accrual' | 'anticipation' | 'action';

interface AuditEvent {
  category: AuditCategory;
  eventType: string;
  description: string;
  organizationId?: string;
  actorId?: string;
  actorRole?: UserRole;
  actorLayer?: RoleLayer;
  targetType?: string;
  targetId?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Record an audit event. Append-only — the database trigger prevents
 * any UPDATE or DELETE on the audit_trail table. (Tessera v3.1 §11)
 *
 * Returns the event ID and hash for FORAY transaction linking.
 */
export async function recordAuditEvent(
  event: AuditEvent
): Promise<{ eventId: string; eventHash: string }> {
  const eventId = uuidv4();
  const metadata = event.metadata || {};

  // Compute SHA-512 hash of event data for integrity verification.
  // This hash is included in the FORAY transaction for blockchain anchoring.
  const hashInput = JSON.stringify({
    id: eventId,
    timestamp: new Date().toISOString(),
    category: event.category,
    eventType: event.eventType,
    description: event.description,
    organizationId: event.organizationId,
    actorId: event.actorId,
    targetType: event.targetType,
    targetId: event.targetId,
    metadata,
  });
  const eventHash = createHash('sha512').update(hashInput).digest('hex');

  await pool.query(
    `INSERT INTO audit_trail
       (id, category, event_type, description, organization_id,
        actor_id, actor_role, actor_layer,
        target_type, target_id, metadata, event_hash)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
    [
      eventId,
      event.category,
      event.eventType,
      event.description,
      event.organizationId || null,
      event.actorId || null,
      event.actorRole || null,
      event.actorLayer || null,
      event.targetType || null,
      event.targetId || null,
      JSON.stringify(metadata),
      eventHash,
    ]
  );

  // TODO: Queue for FORAY Protocol transaction submission.
  // The FORAY integration service (src/foray/) will batch events
  // and commit to Kaspa. If FORAY/Kaspa is unavailable, events
  // remain in the local audit_trail with is_anchored = false
  // and are committed on reconnection. (Tessera v3.1 §11.4)

  return { eventId, eventHash };
}

/**
 * Query audit events with filtering. Read-only.
 * Available to auditor role. (Tessera v3.1 §4, §11.2)
 */
export async function queryAuditEvents(filters: {
  organizationId?: string;
  category?: AuditCategory;
  eventType?: string;
  actorId?: string;
  targetType?: string;
  targetId?: string;
  from?: Date;
  to?: Date;
  limit?: number;
  offset?: number;
}) {
  const conditions: string[] = [];
  const params: any[] = [];
  let paramIndex = 1;

  if (filters.organizationId) {
    conditions.push(`organization_id = $${paramIndex++}`);
    params.push(filters.organizationId);
  }
  if (filters.category) {
    conditions.push(`category = $${paramIndex++}`);
    params.push(filters.category);
  }
  if (filters.eventType) {
    conditions.push(`event_type = $${paramIndex++}`);
    params.push(filters.eventType);
  }
  if (filters.actorId) {
    conditions.push(`actor_id = $${paramIndex++}`);
    params.push(filters.actorId);
  }
  if (filters.targetType) {
    conditions.push(`target_type = $${paramIndex++}`);
    params.push(filters.targetType);
  }
  if (filters.targetId) {
    conditions.push(`target_id = $${paramIndex++}`);
    params.push(filters.targetId);
  }
  if (filters.from) {
    conditions.push(`event_time >= $${paramIndex++}`);
    params.push(filters.from);
  }
  if (filters.to) {
    conditions.push(`event_time <= $${paramIndex++}`);
    params.push(filters.to);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const limit = filters.limit || 50;
  const offset = filters.offset || 0;

  const result = await pool.query(
    `SELECT id, event_time, category, event_type, description,
            organization_id, actor_id, actor_role, actor_layer,
            target_type, target_id, metadata, event_hash,
            foray_tx_id, kaspa_tx_id, is_anchored, anchored_at
     FROM audit_trail
     ${where}
     ORDER BY event_time DESC
     LIMIT ${limit} OFFSET ${offset}`,
    params
  );

  return result.rows;
}
