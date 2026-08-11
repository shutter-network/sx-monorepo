/**
 * Cross-implementation test vectors. Loads every JSON file under
 * `tests/vectors/<category>/` and re-runs the SDK's verify path.
 * An independent re-verifier in another language consumes the same
 * files; if this test and theirs both green, the wire-level contract
 * matches. See `tests/vectors/_schema.ts` for the JSON shape and
 * `scripts/gen-vectors.ts` for the generator.
 *
 * The assertions themselves live in `tests/lib/vectorSuite.ts`, shared with
 * `geg-parity.test.ts` which runs the identical checks over geg's canonical
 * corpus. Keeping one runner is what stops the two from drifting.
 */

import { join } from 'node:path';
import { initCurves } from '../src';
import { listAllVectorFiles, registerVectorSuite } from './lib/vectorSuite';

beforeAll(async () => {
  await initCurves();
});

const VECTORS_DIR = join(__dirname, 'vectors');

describe('cross-impl vectors', () => {
  const handled = registerVectorSuite(VECTORS_DIR);

  it('covers every vector file on disk', () => {
    const all = listAllVectorFiles(VECTORS_DIR);
    expect(all.length).toBeGreaterThan(0);
    expect([...handled].sort()).toEqual(all);
  });
});
