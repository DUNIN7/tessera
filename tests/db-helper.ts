// =============================================================================
// TESSERA — Test Database Helper
//
// Direct database access for test setup and teardown.
// Only used for test data seeding — all assertions go through the HTTP API.
// =============================================================================

import { Pool } from 'pg';
import { createHash } from 'crypto';

const testPool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgres://dbl8@localhost:5432/tessera',
  max: 3,
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 10000,
});

/** Clean up test data created during test runs */
export async function cleanTestData(): Promise<void> {
  const client = await testPool.connect();
  try {
    await client.query('SET statement_timeout = 8000');
    await client.query('BEGIN');

    const docs = await client.query(`SELECT id FROM documents WHERE title LIKE 'TEST_%'`);
    const docIds = docs.rows.map((r: any) => r.id);

    if (docIds.length > 0) {
      // Get session IDs first (avoids nested subqueries)
      const sessions = await client.query(
        `SELECT id FROM markup_sessions WHERE document_id = ANY($1)`, [docIds]
      );
      const sessionIds = sessions.rows.map((r: any) => r.id);

      if (sessionIds.length > 0) {
        const ops = await client.query(
          `SELECT id FROM markup_operations WHERE session_id = ANY($1)`, [sessionIds]
        );
        const opIds = ops.rows.map((r: any) => r.id);

        if (opIds.length > 0) {
          await client.query(`DELETE FROM markup_selections WHERE operation_id = ANY($1)`, [opIds]);
        }
        await client.query(`DELETE FROM content_set_assignments WHERE session_id = ANY($1)`, [sessionIds]);
        await client.query(`DELETE FROM markup_operations WHERE session_id = ANY($1)`, [sessionIds]);
        await client.query(`DELETE FROM markup_suggestions WHERE session_id = ANY($1)`, [sessionIds]);
        await client.query(`DELETE FROM markup_reviews WHERE session_id = ANY($1)`, [sessionIds]);
        await client.query(`DELETE FROM markup_sessions WHERE id = ANY($1)`, [sessionIds]);
      }

      await client.query(`DELETE FROM reconstruction_events WHERE document_id = ANY($1)`, [docIds]);
      await client.query(`DELETE FROM base_documents WHERE document_id = ANY($1)`, [docIds]);
      await client.query(`DELETE FROM encrypted_content_sets WHERE document_id = ANY($1)`, [docIds]);
      await client.query(`DELETE FROM encryption_keys WHERE document_id = ANY($1)`, [docIds]);
      await client.query(`DELETE FROM positional_markers WHERE document_id = ANY($1)`, [docIds]);
      await client.query(`DELETE FROM user_access_grants WHERE document_id = ANY($1)`, [docIds]);

      const csets = await client.query(
        `SELECT id FROM content_sets WHERE document_id = ANY($1)`, [docIds]
      );
      const csIds = csets.rows.map((r: any) => r.id);
      if (csIds.length > 0) {
        await client.query(`DELETE FROM access_level_content_sets WHERE content_set_id = ANY($1)`, [csIds]);
      }
      await client.query(`DELETE FROM content_sets WHERE document_id = ANY($1)`, [docIds]);
      await client.query(`DELETE FROM documents WHERE id = ANY($1)`, [docIds]);
    }

    // Clean test access levels
    const levels = await client.query(`SELECT id FROM access_levels WHERE name LIKE 'TEST_%'`);
    const levelIds = levels.rows.map((r: any) => r.id);
    if (levelIds.length > 0) {
      await client.query(`DELETE FROM access_level_content_sets WHERE access_level_id = ANY($1)`, [levelIds]);
      await client.query(`DELETE FROM access_levels WHERE id = ANY($1)`, [levelIds]);
    }

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.warn('cleanTestData warning:', (err as Error).message);
  } finally {
    await client.query('RESET statement_timeout').catch(() => {});
    client.release();
  }
}

/**
 * Insert a test document directly, already at 'intake_cleared' status.
 */
export async function seedTestDocument(params?: {
  title?: string;
  orgId?: string;
}): Promise<string> {
  const title = params?.title || `TEST_doc_${Date.now()}`;
  const orgId = params?.orgId || 'a0000000-0000-0000-0000-000000000001';
  const client = await testPool.connect();
  try {
    const hash = createHash('sha512').update(title).digest('hex');
    const result = await client.query(
      `INSERT INTO documents
         (organization_id, title, original_filename, mime_type,
          original_size_bytes, original_hash, normalized_hash, status)
       VALUES ($1, $2, $3, 'text/plain', 2048, $4, $4, 'intake_cleared')
       RETURNING id`,
      [orgId, title, `${title}.txt`, hash]
    );
    return result.rows[0].id;
  } finally {
    client.release();
  }
}

/**
 * Seed content sets for a document.
 */
export async function seedContentSets(
  documentId: string,
  orgId: string = 'a0000000-0000-0000-0000-000000000001',
  sets: Array<{ identifier: string; label: string }> = [
    { identifier: 'CS-PUBLIC', label: 'Public' },
    { identifier: 'CS-CONFIDENTIAL', label: 'Confidential' },
    { identifier: 'CS-SECRET', label: 'Secret' },
  ],
): Promise<Array<{ id: string; identifier: string }>> {
  const client = await testPool.connect();
  const results: Array<{ id: string; identifier: string }> = [];
  try {
    for (const set of sets) {
      const result = await client.query(
        `INSERT INTO content_sets (document_id, organization_id, set_identifier, label)
         VALUES ($1, $2, $3, $4) RETURNING id`,
        [documentId, orgId, set.identifier, set.label]
      );
      results.push({ id: result.rows[0].id, identifier: set.identifier });
    }
    return results;
  } finally {
    client.release();
  }
}

/**
 * Seed an access level and link it to specific content sets.
 */
export async function seedAccessLevel(params: {
  name: string;
  orgId?: string;
  contentSetIds: string[];
  exportPermitted?: boolean;
}): Promise<string> {
  const orgId = params.orgId || 'a0000000-0000-0000-0000-000000000001';
  const client = await testPool.connect();
  try {
    const result = await client.query(
      `INSERT INTO access_levels (organization_id, name, export_permitted)
       VALUES ($1, $2, $3) RETURNING id`,
      [orgId, params.name, params.exportPermitted ?? false]
    );
    const levelId = result.rows[0].id;
    for (const csId of params.contentSetIds) {
      await client.query(
        `INSERT INTO access_level_content_sets (access_level_id, content_set_id)
         VALUES ($1, $2)`,
        [levelId, csId]
      );
    }
    return levelId;
  } finally {
    client.release();
  }
}

/**
 * Grant a user access at a specific access level for a document.
 */
export async function seedUserGrant(params: {
  userId: string;
  documentId: string;
  accessLevelId: string;
}): Promise<string> {
  const client = await testPool.connect();
  try {
    const result = await client.query(
      `INSERT INTO user_access_grants
         (user_id, document_id, access_level_id, granted_by)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [params.userId, params.documentId, params.accessLevelId,
       'b0000000-0000-0000-0000-000000000002']
    );
    return result.rows[0].id;
  } finally {
    client.release();
  }
}

/** Get document status from DB */
export async function getDocumentStatus(docId: string): Promise<string> {
  const result = await testPool.query(
    `SELECT status FROM documents WHERE id = $1`, [docId]
  );
  return result.rows[0]?.status;
}

/** Shutdown the test pool */
export async function closeTestPool(): Promise<void> {
  await testPool.end();
}

export { testPool };
