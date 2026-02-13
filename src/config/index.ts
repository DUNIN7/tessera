// =============================================================================
// TESSERA — Application Configuration
// Loads from environment variables with defaults for development.
//
// Spec Reference: §10.4 (session/auth), §10.6 (security profiles)
// =============================================================================

export const config = {
  port: parseInt(process.env.PORT || '3100', 10),
  nodeEnv: process.env.NODE_ENV || 'development',

  db: {
    connectionString: process.env.DATABASE_URL || 'postgres://tessera:tessera_dev_only@localhost:5433/tessera',
  },

  jwt: {
    secret: process.env.JWT_SECRET || 'tessera_dev_jwt_secret_change_in_production',
    expiry: process.env.JWT_EXPIRY || '15m',
  },

  // Spec §10.4: 15-minute inactivity timeout, mandatory re-authentication
  session: {
    inactivityTimeoutSeconds: parseInt(process.env.SESSION_INACTIVITY_TIMEOUT || '900', 10),
  },

  foray: {
    apiUrl: process.env.FORAY_API_URL || 'https://foray.dunin7.com',
  },

  logging: {
    level: process.env.LOG_LEVEL || 'info',
  },
} as const;
