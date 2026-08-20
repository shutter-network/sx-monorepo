import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { deriveMaxWeight } from '../../src/helpers/gegConfig';

describe('deriveMaxWeight', () => {
  // The sequencer keeps its own copy: it clamps with maxWeight before minting a
  // credential, while the hub advertises the same figure in the election config
  // the committee verifies against. If the two drift, the sequencer attests
  // weights the committee rejects as INVALID_ATTESTATION and every over-cap
  // ballot silently leaves the tally.
  //
  // Both sides assert against one shared table rather than importing each other:
  // a cross-app TypeScript import escapes each package's rootDir, and comparing
  // the two implementations directly would pass if both drifted together.
  // `apps/sequencer/test/unit/helpers/teCommittee.test.ts` asserts the same file.
  it('matches the shared parity table', () => {
    const table = JSON.parse(
      readFileSync(
        join(
          __dirname,
          '../../../../packages/geg-parity/vectors/max-weight.json'
        ),
        'utf8'
      )
    );
    expect(table.cases.length).toBeGreaterThan(0);
    for (const c of table.cases) {
      expect(deriveMaxWeight(c.budget)).toBe(c.maxWeight);
    }
  });

  it('never exceeds the protocol bound', () => {
    for (let budget = 1; budget <= 2000; budget++) {
      expect(budget * deriveMaxWeight(budget)).toBeLessThanOrEqual(1_000_000);
    }
  });
});
