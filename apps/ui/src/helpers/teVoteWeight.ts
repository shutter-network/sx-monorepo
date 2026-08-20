/**
 * What a private proposal will actually count this voter as, decided before they
 * sign rather than after.
 *
 * Voting power on a `shutter-elgamal` proposal is not used as given: the protocol
 * counts in whole numbers and caps them, so a holder of 25,000 is counted at
 * 10,000 and a holder of 0.3 cannot vote at all. Both were previously invisible
 * until the moment of truth — the clamp only showed up in the verify panel after
 * the tally, and the floor showed up as a rejection *after* the voter had already
 * picked choices and signed an EIP-712 message.
 *
 * **This is advisory only.** The sequencer decides; it refuses dust at ingest and
 * clamps before minting the credential. This exists so the outcome is not a
 * surprise, not to enforce anything.
 *
 * It is a fourth copy of a rule that also lives in the sequencer (ingest) and the
 * verify panel (recomputation), so `teVoteWeight.test.ts` pins it against the
 * shared parity table rather than trusting three implementations to agree.
 */

import { TE_MAX_WEIGHT, TE_MAX_WEIGHT_UNWEIGHTED } from './constants';

export type TeVoteWeight =
  | { kind: 'ok'; counted: number; maxWeight: number }
  /** Voting power exceeds the ceiling; counted *at* the ceiling, not dropped. */
  | { kind: 'clamped'; counted: number; maxWeight: number }
  /** Rounds to zero weight, so the sequencer will refuse the vote outright. */
  | { kind: 'dust'; counted: 0; maxWeight: number };

/**
 * The ceiling for a proposal, which follows its ballot budget: weighted voting
 * spends a budget of `TE_WEIGHTED_BUDGET`, everything else spends 1.
 */
export function teMaxWeightForType(type: string): number {
  return type === 'weighted' ? TE_MAX_WEIGHT : TE_MAX_WEIGHT_UNWEIGHTED;
}

/**
 * Must stay identical to `isDustVotingPower` and the clamp in
 * `apps/sequencer/src/writer/vote.ts`. A disagreement here shows the voter a
 * figure the tally will not honour, which is worse than showing nothing.
 */
export function teVoteWeight(vp: number, type: string): TeVoteWeight {
  const maxWeight = teMaxWeightForType(type);

  if (!Number.isFinite(vp) || Math.round(vp) < 1) {
    return { kind: 'dust', counted: 0, maxWeight };
  }
  const rounded = Math.round(vp);
  return rounded > maxWeight
    ? { kind: 'clamped', counted: maxWeight, maxWeight }
    : { kind: 'ok', counted: rounded, maxWeight };
}

/** The same figure `getFormattedVotingPower` renders, as a plain number. */
export function totalVotingPower(votingPower?: {
  votingPowers: { value: bigint; cumulativeDecimals: number }[];
}): number | null {
  if (!votingPower?.votingPowers?.length) return null;
  return votingPower.votingPowers.reduce(
    (acc, b) => acc + Number(b.value) / 10 ** b.cumulativeDecimals,
    0
  );
}
