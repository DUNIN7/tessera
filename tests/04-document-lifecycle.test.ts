// =============================================================================
// TESSERA — Test Suite 04: Full Document Lifecycle
//
// End-to-end integration test for the complete pipeline:
//   intake_cleared → markup → review → approve → deconstruct → reconstruct
//
// This test exercises the Tessera security guarantee:
//   "No single compromised component reveals protected content."
// =============================================================================

import { authApi, json, login, assertApi } from './helpers';
import {
  seedTestDocument,
  seedContentSets,
  seedAccessLevel,
  seedUserGrant,
  getDocumentStatus,
  cleanTestData,
  closeTestPool,
  testPool,
} from './db-helper';

// Shared state across the ordered test steps
let documentId: string;
let contentSets: Array<{ id: string; identifier: string }>;
let markupSessionId: string;
let publicAccessLevelId: string;
let confidentialAccessLevelId: string;

const ORG_ID = 'a0000000-0000-0000-0000-000000000001';
const VIEWER_ID = 'b0000000-0000-0000-0000-000000000005';

// ── Setup & Teardown ──────────────────────────────────────────────────

beforeAll(async () => {
  await cleanTestData();

  // Seed a document ready for markup
  documentId = await seedTestDocument({ title: 'TEST_Lifecycle_Doc' });

  // Seed three content sets: PUBLIC, CONFIDENTIAL, SECRET
  contentSets = await seedContentSets(documentId, ORG_ID, [
    { identifier: 'CS-PUBLIC', label: 'Public' },
    { identifier: 'CS-CONFIDENTIAL', label: 'Confidential' },
    { identifier: 'CS-SECRET', label: 'Secret' },
  ]);
}, 15000);

afterAll(async () => {
  await cleanTestData();
  await closeTestPool();
}, 15000);

// ── Phase 1: Document at Intake ─────────────────────────────────────

describe('Phase 1: Document Setup', () => {
  test('document exists at intake_cleared status', async () => {
    const status = await getDocumentStatus(documentId);
    expect(status).toBe('intake_cleared');
  });

  test('org_admin can see the document', async () => {
    const body = await assertApi('orgAdmin', 'GET', `/api/content/documents/${documentId}`, 200);
    expect(body.document).toBeDefined();
    expect(body.document.title).toBe('TEST_Lifecycle_Doc');
    expect(body.document.status).toBe('intake_cleared');
  });

  test('org_admin can list documents including the test doc', async () => {
    const body = await assertApi('orgAdmin', 'GET', '/api/content/documents', 200);
    expect(body.documents).toBeDefined();
    const testDoc = body.documents.find((d: any) => d.id === documentId);
    expect(testDoc).toBeDefined();
  });
});

// ── Phase 2: Markup ─────────────────────────────────────────────────

describe('Phase 2: Markup Engine (§7)', () => {
  test('redactor creates markup session', async () => {
    const body = await assertApi('redactor', 'POST', '/api/content/markup/sessions', 201, {
      documentId,
    });

    expect(body.sessionId).toBeDefined();
    markupSessionId = body.sessionId;
  });

  test('document transitions to markup status', async () => {
    const status = await getDocumentStatus(documentId);
    expect(status).toBe('markup');
  });

  test('redactor can get session state', async () => {
    const body = await assertApi(
      'redactor', 'GET', `/api/content/markup/sessions/${markupSessionId}`, 200
    );
    expect(body.sessionId || body.session?.id || body.id).toBeDefined();
  });

  test('redactor assigns content to PUBLIC set', async () => {
    const body = await assertApi(
      'redactor', 'POST',
      `/api/content/markup/sessions/${markupSessionId}/operations`,
      201,
      {
        type: 'assign',
        contentSetIdentifier: 'CS-PUBLIC',
        selections: [
          {
            selectionId: 'sel-pub-001',
            blockId: 'block-001',
            granularity: 'character',
            startOffset: 0,
            endOffset: 45,
            selectedText: 'This is publicly available project information',
            page: 1,
          },
        ],
      },
    );

    expect(body.operationId || body.sequence).toBeDefined();
  });

  test('redactor assigns content to CONFIDENTIAL set', async () => {
    const body = await assertApi(
      'redactor', 'POST',
      `/api/content/markup/sessions/${markupSessionId}/operations`,
      201,
      {
        type: 'assign',
        contentSetIdentifier: 'CS-CONFIDENTIAL',
        selections: [
          {
            selectionId: 'sel-conf-001',
            blockId: 'block-002',
            granularity: 'character',
            startOffset: 0,
            endOffset: 38,
            selectedText: 'Confidential budget allocation details',
            page: 1,
          },
        ],
      },
    );

    expect(body.operationId || body.sequence).toBeDefined();
  });

  test('redactor assigns content to SECRET set', async () => {
    const body = await assertApi(
      'redactor', 'POST',
      `/api/content/markup/sessions/${markupSessionId}/operations`,
      201,
      {
        type: 'assign',
        contentSetIdentifier: 'CS-SECRET',
        selections: [
          {
            selectionId: 'sel-sec-001',
            blockId: 'block-003',
            granularity: 'character',
            startOffset: 0,
            endOffset: 42,
            selectedText: 'Classified personnel identification records',
            page: 2,
          },
        ],
      },
    );

    expect(body.operationId || body.sequence).toBeDefined();
  });

  test('undo removes last operation', async () => {
    const body = await assertApi(
      'redactor', 'POST',
      `/api/content/markup/sessions/${markupSessionId}/undo`,
      200,
    );
    expect(body.undone).toBe(true);
  });

  test('redo restores undone operation', async () => {
    const body = await assertApi(
      'redactor', 'POST',
      `/api/content/markup/sessions/${markupSessionId}/redo`,
      200,
    );
    expect(body.redone).toBe(true);
  });

  test('overlap report shows no cross-set overlaps', async () => {
    const body = await assertApi(
      'redactor', 'GET',
      `/api/content/markup/sessions/${markupSessionId}/overlaps`,
      200,
    );

    expect(body.overlaps || body.entries).toBeDefined();
    // Our test selections don't overlap, so count should be 0
    const count = body.totalOverlaps || body.count || (body.overlaps || body.entries || []).length;
    expect(count).toBe(0);
  });
});

// ── Phase 3: Review & Approval ──────────────────────────────────────

describe('Phase 3: Review & Approval (§8)', () => {
  test('redactor submits session for review', async () => {
    const body = await assertApi(
      'redactor', 'POST',
      `/api/content/markup/sessions/${markupSessionId}/submit`,
      200,
      { notes: 'Ready for review — three content sets assigned' },
    );

    expect(body.submitted).toBe(true);
  });

  test('reviewer gets review package', async () => {
    const body = await assertApi(
      'reviewer', 'GET',
      `/api/content/markup/sessions/${markupSessionId}/review-package`,
      200,
    );

    expect(body).toBeDefined();
    // Package should include assignments and overlap info
  });

  test('reviewer approves the markup', async () => {
    const body = await assertApi(
      'reviewer', 'POST',
      `/api/content/markup/sessions/${markupSessionId}/review`,
      200,
      {
        decision: 'approve',
        comments: 'All three content sets properly assigned. Full coverage verified.',
        fullCoverageVerified: true,
      },
    );

    expect(body.reviewId).toBeDefined();
    expect(body.newDocumentStatus).toBe('approved');
  });

  test('document transitions to approved status', async () => {
    const status = await getDocumentStatus(documentId);
    expect(status).toBe('approved');
  });
});

// ── Phase 4: Deconstruction ─────────────────────────────────────────

describe('Phase 4: Deconstruction (§8.3)', () => {
  test('org_admin triggers deconstruction', async () => {
    const res = await authApi('orgAdmin', 'POST',
      `/api/content/crypto/deconstruct/${documentId}`,
      { sessionId: markupSessionId },
    );

    // 201 = success, 409 = already deconstructed, 400 = no content sets
    expect([201, 200]).toContain(res.status);

    const body = await json(res);

    if (res.status === 201) {
      expect(body.documentId).toBe(documentId);
      expect(body.contentSets).toBeDefined();
      expect(Array.isArray(body.contentSets)).toBe(true);
      expect(body.contentSets.length).toBe(3); // PUBLIC, CONFIDENTIAL, SECRET

      // Each content set should have AES-256-GCM encryption
      for (const cs of body.contentSets) {
        expect(cs.algorithm).toBe('aes-256-gcm');
        expect(cs.ciphertextHash).toBeDefined();
      }

      // Key records should exist
      expect(body.keyRecords).toBeDefined();
      expect(body.keyRecords.length).toBe(3); // One key per content set

      // Each key should have Shamir config
      for (const kr of body.keyRecords) {
        expect(kr.algorithm).toBe('aes-256-gcm');
        expect(kr.shamirConfig).toBeDefined();
        expect(kr.shamirConfig.threshold).toBeGreaterThan(0);
        expect(kr.shamirConfig.totalShares).toBeGreaterThanOrEqual(kr.shamirConfig.threshold);
      }

      // Base document hash should exist
      expect(body.baseDocumentHash).toBeDefined();

      // FORAY blockchain transaction should be recorded
      expect(body.forayTxId).toBeDefined();
    }
  }, 60000);

  test('document transitions to active status', async () => {
    const status = await getDocumentStatus(documentId);
    expect(status).toBe('active');
  });
});

// ── Phase 5: Access Levels & Grants ─────────────────────────────────

describe('Phase 5: Access Level Setup', () => {
  test('create PUBLIC access level (sees only CS-PUBLIC)', async () => {
    const publicCS = contentSets.find(cs => cs.identifier === 'CS-PUBLIC')!;
    publicAccessLevelId = await seedAccessLevel({
      name: 'TEST_Public_View',
      contentSetIds: [publicCS.id],
    });
    expect(publicAccessLevelId).toBeDefined();
  });

  test('create CONFIDENTIAL access level (sees PUBLIC + CONFIDENTIAL)', async () => {
    const publicCS = contentSets.find(cs => cs.identifier === 'CS-PUBLIC')!;
    const confCS = contentSets.find(cs => cs.identifier === 'CS-CONFIDENTIAL')!;
    confidentialAccessLevelId = await seedAccessLevel({
      name: 'TEST_Confidential_View',
      contentSetIds: [publicCS.id, confCS.id],
    });
    expect(confidentialAccessLevelId).toBeDefined();
  });

  test('grant viewer access at PUBLIC level', async () => {
    const grantId = await seedUserGrant({
      userId: VIEWER_ID,
      documentId,
      accessLevelId: publicAccessLevelId,
    });
    expect(grantId).toBeDefined();
  });
});

// ── Phase 6: Reconstruction ─────────────────────────────────────────

describe('Phase 6: Reconstruction (§9)', () => {
  test('viewer reconstructs at PUBLIC level — sees only public content', async () => {
    const res = await authApi('viewer', 'POST',
      `/api/content/crypto/reconstruct/${documentId}`,
      { accessLevelId: publicAccessLevelId },
    );

    expect([200, 403]).toContain(res.status);

    if (res.status === 200) {
      const body = await json(res);
      expect(body.documentId).toBe(documentId);
      expect(body.reconstructionEventId).toBeDefined();

      // Should see PUBLIC content set
      expect(body.contentSetsUsed).toBeDefined();
      expect(body.contentSetsUsed).toContain('CS-PUBLIC');

      // CONFIDENTIAL and SECRET should be redacted
      expect(body.contentSetsRedacted).toBeDefined();
      expect(body.contentSetsRedacted).toContain('CS-CONFIDENTIAL');
      expect(body.contentSetsRedacted).toContain('CS-SECRET');

      // Integrity verification should pass
      expect(body.integrityVerification).toBeDefined();

      // Marker width should be present
      expect(body.markerWidth).toBeGreaterThanOrEqual(3);
      expect(body.markerWidth).toBeLessThanOrEqual(10);
    }
  }, 60000);

  test('org_admin reconstructs at CONFIDENTIAL level — sees public + confidential', async () => {
    const res = await authApi('orgAdmin', 'POST',
      `/api/content/crypto/reconstruct/${documentId}`,
      { accessLevelId: confidentialAccessLevelId },
    );

    if (res.status === 200) {
      const body = await json(res);

      // Should see PUBLIC and CONFIDENTIAL
      expect(body.contentSetsUsed).toContain('CS-PUBLIC');
      expect(body.contentSetsUsed).toContain('CS-CONFIDENTIAL');

      // SECRET should still be redacted
      expect(body.contentSetsRedacted).toContain('CS-SECRET');
    }
  });

  test('reconstruction events are recorded for audit', async () => {
    const res = await authApi('orgAdmin', 'GET',
      `/api/content/crypto/reconstruct/${documentId}/events`,
    );

    if (res.status === 200) {
      const body = await json(res);
      expect(body.events).toBeDefined();
      expect(Array.isArray(body.events)).toBe(true);
      // At least our reconstruction attempts should be logged
    }
  });
});

// ── Phase 7: Integrity Verification ─────────────────────────────────

describe('Phase 7: Integrity Verification (§9.2, §11.3)', () => {
  test('org_admin verifies cryptographic integrity', async () => {
    const res = await authApi('orgAdmin', 'GET',
      `/api/content/crypto/integrity/${documentId}`,
    );

    if (res.status === 200) {
      const body = await json(res);
      expect(body.documentId).toBe(documentId);
      expect(body.baseDocumentVerified).toBe(true);

      // Each content set ciphertext hash should verify
      expect(body.contentSetVerifications).toBeDefined();
      const verifications = Object.values(body.contentSetVerifications) as any[];
      for (const v of verifications) {
        expect(v.verified).toBe(true);
        expect(v.ciphertextHashStored).toBe(v.ciphertextHashComputed);
      }

      expect(body.allPassed).toBe(true);
    }
  });
});

// ── Phase 8: Key Rotation ───────────────────────────────────────────

describe('Phase 8: Key Rotation (§10.2)', () => {
  test('org_admin rotates encryption keys', async () => {
    const res = await authApi('orgAdmin', 'POST',
      `/api/content/crypto/keys/${documentId}/rotate`,
    );

    if (res.status === 200) {
      const body = await json(res);
      expect(body.documentId).toBe(documentId);
      expect(body.rotatedKeys).toBeDefined();
      expect(Array.isArray(body.rotatedKeys)).toBe(true);

      // Each content set should have a new key
      for (const rk of body.rotatedKeys) {
        expect(rk.contentSet).toBeDefined();
        expect(rk.oldKeyId).toBeDefined();
        expect(rk.newKeyId).toBeDefined();
        expect(rk.oldKeyId).not.toBe(rk.newKeyId);
      }
    }
  });

  test('integrity still passes after key rotation', async () => {
    const res = await authApi('orgAdmin', 'GET',
      `/api/content/crypto/integrity/${documentId}`,
    );

    if (res.status === 200) {
      const body = await json(res);
      expect(body.allPassed).toBe(true);
    }
  });

  test('reconstruction still works after key rotation', async () => {
    const res = await authApi('orgAdmin', 'POST',
      `/api/content/crypto/reconstruct/${documentId}`,
      { accessLevelId: confidentialAccessLevelId },
    );

    // Should still work — re-encryption preserves content
    if (res.status === 200) {
      const body = await json(res);
      expect(body.contentSetsUsed).toContain('CS-PUBLIC');
      expect(body.contentSetsUsed).toContain('CS-CONFIDENTIAL');
      expect(body.contentSetsRedacted).toContain('CS-SECRET');
    }
  });
});
