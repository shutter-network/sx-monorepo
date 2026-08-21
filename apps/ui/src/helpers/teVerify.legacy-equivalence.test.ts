/**
 * The replacement tally must compute what the deleted one computed.
 *
 * The pre-geg sequencer summed ballots itself; the committee does it now, and the
 * verify panel recomputes it a third time for the audit surface. The plan's Phase 4
 * exit gate asked for the legacy outputs to be captured before deletion as a
 * permanent regression guard. They were not, so the corpus was reconstructed from
 * `master:apps/sequencer/src/helpers/te.ts` — see
 * `scripts/geg/gen-legacy-equivalence.ts`.
 *
 * The corpus deliberately does **not** claim blanket equivalence. Legacy rounded
 * voting power and dropped what rounded to zero, but it never clamped. Current
 * behaviour clamps at `maxWeight`. A fixture asserting the two agree on a whale
 * would be pinning behaviour that was changed on purpose, and would have to be
 * deleted the first time it failed — so the over-cap case records both answers
 * instead of asserting one.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { aggregateBallots } from './teVerify';

type Agg = {
  election_id: string;
  num_candidates: number;
  ciphertexts: { c1: string; c2: string }[];
};

const corpus = JSON.parse(
  readFileSync(
    join(
      __dirname,
      '../../../../packages/geg-parity/vectors/legacy-equivalence.json'
    ),
    'utf8'
  )
) as {
  proposalId: string;
  numCandidates: number;
  maxWeight: number;
  equivalent: { ballots: any[]; aggregate: Agg };
  divergent: { ballots: any[]; legacyAggregate: Agg; currentAggregate: Agg };
  boundary: {
    totalAdmittedWeight: string;
    asJsNumber: number;
    exactRoundTrip: string;
  };
};

function payload(ballots: any[], maxWeight: number | null) {
  return {
    te_mpk: `0x${'00'.repeat(96)}`,
    te_config: {
      numCandidates: corpus.numCandidates,
      budget: 100,
      mode: 'exact',
      variant: 'A'
    },
    maxWeight,
    ballots
  } as any;
}

describe('legacy equivalence', () => {
  beforeAll(() => {
    expect(corpus.equivalent.ballots.length).toBeGreaterThan(0);
  });

  // The actual guard: same ballots, same weights, same sum as the deleted code.
  it('reproduces the legacy aggregate where no weight was clamped', async () => {
    const result = await aggregateBallots(
      payload(corpus.equivalent.ballots, corpus.maxWeight),
      corpus.equivalent.aggregate as any
    );
    expect(result.aggregateMatches).toBe(true);
    expect(result.clamped).toEqual([]);
  });

  // Rounding is part of what must not drift: 1.4 → 1 and 0.5 → 1 both count once,
  // so five ballots contribute even though two of them hold less than 2.
  it('counts every in-cap ballot, including the rounded ones', async () => {
    const result = await aggregateBallots(
      payload(corpus.equivalent.ballots, corpus.maxWeight),
      corpus.equivalent.aggregate as any
    );
    expect(result.contributing).toBe(corpus.equivalent.ballots.length);
  });

  // Documented divergence, asserted in both directions so neither can drift
  // unnoticed: current must match its own answer, and must *not* match legacy's.
  it('diverges from legacy on an over-cap ballot, by design', async () => {
    const matchesCurrent = await aggregateBallots(
      payload(corpus.divergent.ballots, corpus.maxWeight),
      corpus.divergent.currentAggregate as any
    );
    expect(matchesCurrent.aggregateMatches).toBe(true);
    expect(matchesCurrent.clamped).toHaveLength(1);
    expect(matchesCurrent.clamped[0].countedAs).toBe(corpus.maxWeight);

    const matchesLegacy = await aggregateBallots(
      payload(corpus.divergent.ballots, corpus.maxWeight),
      corpus.divergent.legacyAggregate as any
    );
    expect(matchesLegacy.aggregateMatches).toBe(false);
  });

  // With no ceiling supplied the panel counts the whale in full — which is what
  // legacy did, and is why the two agree again once the cap is removed. This is
  // the assertion that proves the divergence is the cap and nothing else.
  it('reproduces legacy exactly when the cap is absent', async () => {
    const result = await aggregateBallots(
      payload(corpus.divergent.ballots, null),
      corpus.divergent.legacyAggregate as any
    );
    expect(result.aggregateMatches).toBe(true);
    expect(result.clamped).toEqual([]);
  });

  // The float boundary the digest encoding exists for: past 2^53 a JS number is no
  // longer the value it was given, so a total admitted weight carried as a number
  // changes the digest and no quorum forms.
  it('records that a total past 2^53 is not exact as a number', () => {
    expect(String(corpus.boundary.asJsNumber)).not.toBe(
      corpus.boundary.exactRoundTrip
    );
    expect(BigInt(corpus.boundary.totalAdmittedWeight).toString()).toBe(
      corpus.boundary.exactRoundTrip
    );
  });
});
