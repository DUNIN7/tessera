// =============================================================================
// TESSERA — Database Connection Pool
// =============================================================================

import { Pool } from 'pg';
import { config } from '../config';

export const pool = new Pool({
  connectionString: config.db.connectionString,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  console.error('[DB] Unexpected pool error:', err.message);
});
