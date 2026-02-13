# TESSERA

**Secure Document Redaction & Access Control System**

Tessera enables organizations to selectively control access to document content based on configurable access levels. Documents are deconstructed into separately encrypted content sets, stored across physically separated locations, and reconstructed into tailored views where inaccessible content is replaced with standardized redaction markers.

No single party — including system operators — can unilaterally reconstruct a complete document.

```
Owner / Licensor    Marvin Percival
Contact             marvinp@dunin7.com
Repository          github.com/DUNIN7/tessera
License             Business Source License 1.1 (BSL 1.1)
Related Project     FORAY Protocol — foray.dunin7.com
Organization        DUNIN7 (Done In Seven)
```

---

## How It Works

Tessera's name refers to the individual tiles in a mosaic. Each content set is a tessera; the complete document is the mosaic, visible only when the right pieces are assembled together.

```
┌─────────────────────────────────────────────────────────────┐
│  DOCUMENT INTAKE                                             │
│  Upload → Validate → Normalize → Stego Scan → Register      │
│                                                    ↓ FORAY   │
├─────────────────────────────────────────────────────────────┤
│  MARKUP                                                      │
│  Redactor assigns content to sets (one set at a time)        │
│  AI suggestions (advisory only) · Pattern matching           │
│  Undo/redo · Cross-set overlap detection                     │
├─────────────────────────────────────────────────────────────┤
│  APPROVAL                                                    │
│  Reviewer verifies markup · Overlap report · Stego report    │
│  Approve / Reject / Escalate → Org Admin arbitration         │
│                                                    ↓ FORAY   │
├─────────────────────────────────────────────────────────────┤
│  DECONSTRUCTION                                              │
│  Base document + positional markers                          │
│  Each content set → AES-256-GCM (unique key per set)         │
│  Keys → Shamir's Secret Sharing (M-of-N)                     │
│  Encrypted sets → physically separated storage               │
│                                                    ↓ FORAY   │
├─────────────────────────────────────────────────────────────┤
│  RECONSTRUCTION                                              │
│  Viewer authorized → content sets decrypted → integrity      │
│  verified → tailored view assembled                          │
│  Inaccessible content → ███ (configurable width 3–10)        │
│                                                    ↓ FORAY   │
└─────────────────────────────────────────────────────────────┘
```

Every lifecycle event is recorded on blockchain via FORAY Protocol, anchored to the Kaspa blockDAG.

---

## Security Model

### Core Guarantee

**No single party can unilaterally reconstruct a complete document.** This is enforced structurally:

- System administrators have no access to encryption keys or document content
- Database administrators see only encrypted ciphertext
- Infrastructure operators manage storage but cannot decrypt
- HSM access requires multi-party authorization
- Key reconstruction requires M-of-N Shamir shares from designated holders

### Threat Model

Tessera is designed against seven adversary classes: external attackers, compromised insiders (viewer and operator), compromised storage locations, state-level adversaries, AI/inference adversaries, and steganographic adversaries. See Specification §2 for the complete threat model.

### Encryption

| Layer | Standard |
|-------|----------|
| At rest | AES-256-GCM, unique key per content set |
| In transit | TLS 1.3 minimum |
| Key derivation | HKDF-SHA-512 from master secrets |
| Password hashing | Argon2id |
| Integrity | SHA-512 for all verification |
| Key splitting | Shamir's Secret Sharing (M-of-N threshold) |
| Key storage | HSM (SoftHSM2 in dev, FIPS 140-3 in production) |

### Storage Tiers

| Tier | Separation | Target |
|------|-----------|--------|
| Tier 1 | Separate logical partitions, same data center | Corporate, low-sensitivity |
| Tier 2 | Separate data centers, different teams | Healthcare, legal, financial |
| Tier 3 | Separate secure facilities, different jurisdictions | Government, military, intelligence |

### Redaction

All redacted content displays as a uniform-width marker (███) regardless of original content type, length, or nature. Adjacent redacted segments merge into a single marker. Marker width is configurable per organization (3–10 characters, default 3). No invisible or seamless redaction — this is an explicit design decision.

---

## Architecture

```
tessera/
├── .github/workflows/    CI pipeline
├── src/
│   ├── authorization/    Tiered auth provider (conventional RBAC → future Ova Protocol)
│   ├── config/           Environment-based configuration
│   ├── db/               PostgreSQL schemas (applied in order)
│   │   ├── schema.sql          Phase 1 — Foundation (27 tables)
│   │   ├── markup-schema.sql   Phase 3 — Markup Engine (6 tables)
│   │   ├── crypto-schema.sql   Phase 4 — Crypto Core (5 tables)
│   │   ├── phase56-schema.sql  Phase 5+6 — Export, retention, versioning
│   │   └── seed.sql            Development seed data
│   ├── foray/            FORAY Protocol blockchain integration
│   ├── middleware/        Auth, layer guard, tenant isolation, security hardening
│   ├── routes/
│   │   ├── auth.ts             Authentication (login/logout/session)
│   │   ├── content/            Content-layer routes (structurally isolated)
│   │   │   ├── index.ts        Document intake, access levels, user management
│   │   │   ├── markup.ts       Markup engine (17 endpoints)
│   │   │   ├── crypto.ts       Deconstruction/reconstruction (5 endpoints)
│   │   │   └── phase56.ts      Export, versioning, retention, verification
│   │   ├── access-control/     Authorization-layer routes (structurally isolated)
│   │   └── audit/              Audit trail and blockchain verification
│   ├── services/
│   │   ├── crypto/             AES-256-GCM, Shamir SSS, HSM, decon/recon engines
│   │   ├── export/             Document export with mandatory watermarking
│   │   ├── markup/             Sessions, operations, suggestions, approval
│   │   ├── pipeline/           Intake, validation, normalization, stego scanning
│   │   ├── retention/          Data retention policies, verified destruction
│   │   ├── versioning/         Document version chains
│   │   └── audit.ts            Audit event recording
│   ├── types/              TypeScript interfaces for all domains
│   └── server.ts           Express application with security middleware
├── docker-compose.yml      PostgreSQL 16 + app orchestration
├── Dockerfile
├── package.json
└── tsconfig.json
```

### Two-Layer Structural Separation

Content-layer roles (redactor, reviewer, viewer) and access-control-layer roles are structurally separated at the middleware level. Content-layer roles cannot reach `/api/access-control/*` routes. Access-control-layer roles cannot reach `/api/content/*` routes. This is not permission-based — it is structural enforcement.

### Six User Roles

| Role | Layer | Key Constraint |
|------|-------|---------------|
| System Administrator | System | NO access to document content or encryption keys |
| Organization Admin | Content | NO unilateral reconstruction capability |
| Redactor | Content | Document viewing only during active markup session |
| Reviewer/Approver | Content | Must have visibility into all content sets |
| Viewer | Content | Access only at authorized level; all viewing audited |
| Auditor | Content | Read-only audit access; blockchain verification tools |

---

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Node.js 20+ (for local development without Docker)
- FORAY Protocol running (default: `http://localhost:3000`) — see [foray.dunin7.com](https://foray.dunin7.com)

### Quick Start

```bash
# Clone
git clone https://github.com/DUNIN7/tessera.git
cd tessera

# Start everything (PostgreSQL 16 + app on port 3100)
docker compose up

# Verify
curl http://localhost:3100/api/health
```

The database initializes automatically via schema files mounted into PostgreSQL's init directory. Seed data creates a development organization, users for each role, sample access levels, and a security profile.

### Development (Without Docker)

```bash
# Install dependencies
npm install

# Start PostgreSQL separately (or use an existing instance)
# Set DATABASE_URL in .env or environment
export DATABASE_URL=postgres://tessera:tessera_dev_only@localhost:5433/tessera

# Apply schemas in order
psql $DATABASE_URL -f src/db/schema.sql
psql $DATABASE_URL -f src/db/markup-schema.sql
psql $DATABASE_URL -f src/db/crypto-schema.sql
psql $DATABASE_URL -f src/db/phase56-schema.sql
psql $DATABASE_URL -f src/db/seed.sql

# Start dev server (hot reload)
npm run dev
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3100` | Server port |
| `NODE_ENV` | `development` | Environment |
| `DATABASE_URL` | `postgres://tessera:...@db:5432/tessera` | PostgreSQL connection |
| `JWT_SECRET` | dev fallback | JWT signing secret (change in production) |
| `JWT_EXPIRY` | `15m` | Token expiry |
| `SESSION_INACTIVITY_TIMEOUT` | `900` | Session timeout in seconds (§10.4) |
| `FORAY_API_URL` | `http://host.docker.internal:3000` | FORAY Protocol API |
| `TESSERA_UPLOAD_DIR` | `/app/data/uploads` | Document upload storage |
| `TESSERA_NORMALIZED_DIR` | `/app/data/normalized` | Normalized document storage |
| `LOG_LEVEL` | `debug` | Logging verbosity |
| `DB_PASSWORD` | `tessera_dev_only` | Database password |

---

## API Reference

All routes require authentication unless noted. Responses are JSON.

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Login (rate-limited: 20/15min) |
| `POST` | `/api/auth/logout` | Logout |
| `GET` | `/api/auth/session` | Current session info |

### Content Layer (`/api/content/*`)

**Document Management**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/content/documents/upload` | Upload + full intake pipeline |
| `GET` | `/content/documents` | List documents (org-scoped) |
| `GET` | `/content/documents/:id` | Document detail |
| `GET` | `/content/documents/:id/scan` | Stego scan results |
| `POST` | `/content/documents/:id/disposition` | Admin resolve flagged doc |

**Markup Engine (§7, §8)**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/content/markup/sessions` | Create markup session |
| `GET` | `/content/markup/sessions/:id` | Session state + assignments |
| `PATCH` | `/content/markup/sessions/:id/active-set` | Switch active content set |
| `POST` | `/content/markup/sessions/:id/operations` | Execute assign/unassign |
| `POST` | `/content/markup/sessions/:id/undo` | Undo last operation |
| `POST` | `/content/markup/sessions/:id/redo` | Redo |
| `POST` | `/content/markup/sessions/:id/pattern` | Apply regex pattern |
| `POST` | `/content/markup/sessions/:id/propagate` | Find all term occurrences |
| `GET` | `/content/markup/sessions/:id/overlaps` | Cross-set overlap report |
| `POST` | `/content/markup/sessions/:id/suggestions/generate` | Generate AI suggestions |
| `GET` | `/content/markup/sessions/:id/suggestions` | List suggestions |
| `PATCH` | `/content/markup/sessions/:id/suggestions/:sid` | Accept/reject suggestion |
| `POST` | `/content/markup/sessions/:id/submit` | Submit for review |
| `GET` | `/content/markup/sessions/:id/review-package` | Get review package |
| `POST` | `/content/markup/sessions/:id/review` | Record review decision |
| `POST` | `/content/markup/reviews/:id/escalation` | Org admin arbitration |

**Crypto Core (§8.3, §9, §10)**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/content/crypto/deconstruct/:id` | Execute deconstruction |
| `POST` | `/content/crypto/reconstruct/:id` | Reconstruct for viewer |
| `GET` | `/content/crypto/reconstruct/:id/events` | Reconstruction audit log |
| `GET` | `/content/crypto/integrity/:id` | Integrity verification |
| `POST` | `/content/crypto/keys/:id/rotate` | Key rotation |

**Export & Viewing (§9.3, §10.5, §11.2)**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/content/export/:id` | Export with watermark |
| `POST` | `/content/export/:id/viewing-session` | Record viewing session |
| `GET` | `/content/export/:id/events` | Export event audit log |

**Versioning (§14)**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/content/versions/:id/new` | Register new version |
| `GET` | `/content/versions/:id/chain` | Version chain |
| `GET` | `/content/versions/:id/previous-markup` | Previous version markup |

**Retention & Destruction (§12)**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/content/retention/:id/policy` | Retention policy |
| `POST` | `/content/retention/:id/destroy` | Verified destruction |
| `POST` | `/content/retention/:id/destroy-set` | Targeted set destruction (§12.3) |
| `POST` | `/content/retention/:id/legal-hold` | Set/release legal hold |

**Blockchain Verification (§11.3)**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/content/verification/:id/chain-of-custody` | Full audit chain |
| `POST` | `/content/verification/:id/verify` | Integrity verification |

### System

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/api/health` | No | Health check with component status |

---

## Build Phases

| Phase | Scope | Files | Lines | Status |
|-------|-------|-------|-------|--------|
| 1 — Foundation | Auth, RBAC, tenant isolation, FORAY, authorization provider | 25 | 3,204 | ✅ Complete |
| 2 — Document Pipeline | Upload, validate, normalize, stego scan, admin disposition | 33 | 4,679 | ✅ Complete |
| 3 — Markup Engine | Sessions, operations, undo/redo, overlaps, AI suggestions, approval | 37 | 7,303 | ✅ Complete |
| 4 — Crypto Core | AES-256-GCM, Shamir SSS, HSM, deconstruction, reconstruction | 46 | 9,655 | ✅ Complete |
| 5 — Reconstruction | Export/watermark, viewing sessions, versioning, blockchain verification | 53 | 11,472 | ✅ Complete |
| 6 — Hardening | Rate limiting, security headers, session timeout, retention/destruction | 53 | 11,472 | ✅ Complete |

---

## Regulatory Awareness

Tessera tracks the following regulatory frameworks. Full compliance mapping is in progress.

| Regulation | Relevance | Status |
|------------|-----------|--------|
| FedRAMP | US federal cloud deployments | Awareness |
| ITAR | Defense-related technical data | Awareness |
| HIPAA | Protected health information | Awareness |
| GDPR | EU personal data; right-to-erasure | Partially addressed (§12.3) |
| SOX | Financial records audit trail | FORAY provides compatible structure |
| NIST SP 800-171 / CMMC | CUI in defense supply chain | Awareness |
| Common Criteria (ISO 15408) | International security evaluation | Awareness |
| FIPS 140-3 | Cryptographic module validation | Awareness |

---

## Contributing

Tessera is published under BSL 1.1. Contributions are welcome.

### Standard Contributions

Bug fixes, documentation, UI improvements, and non-security features follow the standard pull request and review process.

### Security-Critical Contributions

Modifications to the following modules require **dedicated security review** with a minimum of two designated security reviewers (Specification §16.2):

- Encryption and key management (`src/services/crypto/`)
- Shamir's Secret Sharing implementation
- HSM integration layer
- Deconstruction and reconstruction engines
- Positional marker system
- Blockchain integration and FORAY transaction generation (`src/foray/`)
- Authentication and session management (`src/middleware/authenticate.ts`)
- Steganographic and coded content detection (`src/services/pipeline/stego-scanner.ts`)
- AI model integration and trust boundary enforcement

Security review evaluates: cryptographic correctness, trust boundary preservation, side-channel absence, threat model compliance, and audit trail integrity.

The CI pipeline automatically flags PRs that touch security-critical paths.

### Government and Defense Use

Government and defense organizations may fork and modify Tessera for classified environments without disclosure obligations per BSL 1.1 terms (Specification §16.3).

---

## License

Business Source License 1.1 (BSL 1.1)

Licensor: Marvin Percival

Change date and conversion license are defined in the project's [LICENSE](LICENSE) file.

---

*© 2026 Marvin Percival — DUNIN7*
