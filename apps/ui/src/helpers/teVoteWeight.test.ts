import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { TE_MAX_WEIGHT, TE_MAX_WEIGHT_UNWEIGHTED } from './constants';
import {
  teMaxWeightForType,
  teVoteWeight,
  totalVotingPower
} from './teVoteWeight';

describe('teVoteWeight', () => {
  // The boundaries this exists to tell the voter about, all three confirmed
  // against a live election: 0.3 refused, 0.5 counted as 1, 25,000 capped at
  // 10,000.
  it.each([
    [0.3, 'weighted', 'dust', 0],
    [0.49999, 'weighted', 'dust', 0],
    [0.5, 'weighted', 'ok', 1],
    [1.4, 'weighted', 'ok', 1],
    [1.5, 'weighted', 'ok', 2],
    [1500, 'weighted', 'ok', 1500],
    [10_000, 'weighted', 'ok', 10_000],
    [10_001, 'weighted', 'clamped', 10_000],
    [25_000, 'weighted', 'clamped', 10_000],
    [25_000, 'basic', 'ok', 25_000],
    [2_000_000, 'basic', 'clamped', 1_000_000]
  ])(
    'vp %p on a %s proposal is %s, counted as %p',
    (vp, type, kind, counted) => {
      const r = teVoteWeight(vp as number, type as string);
      expect(r.kind).toBe(kind);
      expect(r.counted).toBe(counted);
    }
  );

  // A non-finite figure must read as dust rather than as countable: `NaN < 1`
  // and `Infinity < 1` are both false, so a bare comparison would tell the voter
  // their vote counts when the sequencer will refuse it.
  it.each([[NaN], [Infinity], [-Infinity]])(
    'treats non-finite vp %p as dust',
    vp => {
      expect(teVoteWeight(vp, 'weighted').kind).toBe('dust');
    }
  );

  it('uses the budget-appropriate ceiling', () => {
    expect(teMaxWeightForType('weighted')).toBe(TE_MAX_WEIGHT);
    expect(teMaxWeightForType('basic')).toBe(TE_MAX_WEIGHT_UNWEIGHTED);
    expect(teMaxWeightForType('single-choice')).toBe(TE_MAX_WEIGHT_UNWEIGHTED);
  });

  // The ceiling is derived in three places — here, the hub's election config, and
  // the sequencer's clamp. All three assert against one shared table, because
  // comparing implementations to each other passes if they drift together.
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
    const weighted = table.cases.find((c: any) => c.budget === 100);
    const basic = table.cases.find((c: any) => c.budget === 1);
    expect(weighted.maxWeight).toBe(TE_MAX_WEIGHT);
    expect(basic.maxWeight).toBe(TE_MAX_WEIGHT_UNWEIGHTED);
  });
});

describe('totalVotingPower', () => {
  it('sums strategies and applies each ones decimals', () => {
    expect(
      totalVotingPower({
        votingPowers: [
          { value: 1_500_000_000_000_000_000_000n, cumulativeDecimals: 18 },
          { value: 500_000_000n, cumulativeDecimals: 6 }
        ]
      })
    ).toBe(2000);
  });

  it('returns null when there is nothing to sum', () => {
    expect(totalVotingPower(undefined)).toBeNull();
    expect(totalVotingPower({ votingPowers: [] })).toBeNull();
  });
});
