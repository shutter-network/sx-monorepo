import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Real end-to-end audit: drive the production-shape `verifyTally` helper
 * inside a Chromium page against a locally orchestrated hub + 3 keypers.
 *
 * Pre-conditions (set up by `python scripts/e2e_orchestrator.py`):
 *   - MySQL running on :3306 with the snapshot_hub schema loaded.
 *   - Hub running on :3000 with a `shutter-elgamal` proposal seeded.
 *   - 3 keypers ran DKG, encrypted a deterministic 2-candidate ballot
 *     [Approve=1, Reject=0] under the joint mpk, and published 6 DLEQ
 *     decryption shares to the hub.
 *   - The proposal id was written to `.e2e-proposal-id`.
 *
 * The spec navigates to the UI dev server, dynamically imports the
 * shipped `teVerify.ts` module, fetches the audit payload from the
 * local hub, runs `verifyTally`, and asserts the recovered tallies
 * exactly equal [1, 0].
 *
 * If any link in the chain (BLST WASM load, transcript binding, DLEQ
 * verify, BSGS) is broken in the UI bundle, this spec fails loudly.
 */

const PROPOSAL_ID = readFileSync(
  resolve(__dirname, '..', '..', '.e2e-proposal-id'),
  'ascii'
).trim();
const HUB_API = 'http://localhost:3000/api';

test.describe('shutter-elgamal audit e2e', () => {
  test('verifyTally recovers [1, 0] from local hub + keypers', async ({
    page
  }) => {
    test.setTimeout(120_000);

    const errors: string[] = [];
    page.on('pageerror', err => errors.push(`pageerror: ${err.message}`));
    page.on('console', msg => {
      if (msg.type() === 'error') errors.push(`console.error: ${msg.text()}`);
    });

    const resp = await page.goto('/');
    expect(resp?.status()).toBeLessThan(400);
    await page.waitForLoadState('networkidle');

    // Eagerly load teBallot so the BLST WASM curves init runs once.
    // verifyTally awaits the same `ensureCurvesInit` internally, but
    // pulling it here surfaces any module-level errors more cleanly.
    const result = await page.evaluate(
      async ({ proposalId, hubApi }) => {
        const teVerify = await import('/src/helpers/teVerify.ts');
        const payload = await teVerify.fetchAuditPayload(hubApi, proposalId);
        // [1, 0] is the published tally for the synthetic ballot the
        // orchestrator encrypts. Passing it bounds BSGS to a tiny
        // table (sumPublished+1 = 2) AND lets `matchesPublished`
        // assert end-to-end correctness in one go.
        const verified = await teVerify.verifyTally(
          proposalId,
          payload,
          [1, 0]
        );
        return {
          tallies: verified.tallies.map(b => b.toString()),
          shareCount: verified.shareCount,
          thresholdMet: verified.thresholdMet,
          matchesPublished: verified.matchesPublished,
          aggregateNumCandidates: payload.aggregate.num_candidates,
          shareSampleKeyperIndex: payload.shares[0]?.keyper_index ?? null
        };
      },
      { proposalId: PROPOSAL_ID, hubApi: HUB_API }
    );

    // The orchestrator encrypts vote=[1, 0]; the audit must recover that
    // exactly. Any crypto regression (transcript drift, DLEQ format,
    // ciphertext encoding, Lagrange combination) shows up here.
    expect(result.tallies).toEqual(['1', '0']);
    expect(result.shareCount).toBe(6);
    expect(result.thresholdMet).toBe(true);
    expect(result.matchesPublished).toBe(true);
    expect(result.aggregateNumCandidates).toBe(2);
    expect(result.shareSampleKeyperIndex).toBeGreaterThanOrEqual(1);

    // No JS errors from the modules we touched in Phases 1–8.
    const ignored = (e: string) =>
      e.includes('GraphQL') ||
      e.includes('Failed to load resource') ||
      e.includes('./gql');
    expect(errors.filter(e => !ignored(e))).toEqual([]);
  });
});
