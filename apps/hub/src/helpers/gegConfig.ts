/**
 * Mapping a Snapshot proposal onto the threshold protocol's election config.
 *
 * The protocol treats an election's config as a frozen artifact and refuses to
 * decode one whose fields are the wrong shape — a single wrong enum value or key
 * name makes every read fail, which is why this mapping lives in exactly one
 * place. The hub is that place: it already links the crypto SDK, and it is the
 * only process that speaks the protocol's JSON.
 *
 * A config has two halves.
 *
 * **Frozen** — committee, threshold, role keys, and the voting window. The
 * sequencer writes these into `proposals.te_geg_config` at proposal creation
 * (see apps/sequencer/src/helpers/teCommittee.ts) and nothing rewrites them.
 *
 * **Derived live** — `numCandidates`, `budget`, `mode`, `variant`. These follow
 * from `choices` and `type`, which an author may edit via `update-proposal` right
 * up until voting opens, so a frozen copy would go stale. Deriving them on every
 * read is safe *because* that endpoint refuses edits once `start` has passed:
 * they are therefore constant across the entire voting window, which is the only
 * window in which they matter. Key generation does not depend on any of them, and
 * no ballot can exist before `start`.
 *
 * Field types worth not guessing at (all confirmed against the protocol's own
 * full-election vector, and all of which raise a decode error if wrong):
 *   - `duplicatePolicy` is the enum *value* `'last-wins'`, not a member name.
 *   - `protocolVersion` is the string `'SHUTTER-VOTE-v1'`, not a number.
 *   - `selfSubmitFee` is a decimal string, not a number (fees exceed 2^53).
 *
 * See docs/private-voting/geg-integration-plan.md §5.
 */

/**
 * Weight ceiling offered to the protocol. Snapshot voting power is uncapped, and
 * capping it here would silently change governance outcomes, so this is set high
 * enough to never bind: it exists to satisfy the protocol's `1 <= weight <= max`
 * check, not to impose policy. 2^53-1 is the largest integer a JSON number can
 * carry losslessly, which is also the ceiling `Math.round(vp)` can produce.
 */
export const MAX_WEIGHT = 9007199254740991;

export const PROTOCOL_VERSION = 'SHUTTER-VOTE-v1';

/** Committee snapshot as the sequencer froze it. */
export interface TeCommitteeSnapshot {
  v: 1;
  keypers: Array<{ address: string; url: string }>;
  thresholdT: number;
  thresholdN: number;
  eligibilityKey: string;
  resultPublisherAddress: string;
  adminAddress: string;
  votingStart: number;
  votingEnd: number;
  weightedBudget: number;
}

/** The protocol's election config, in its exact wire shape. */
export interface GegElectionConfig {
  electionId: string;
  numCandidates: number;
  budget: number;
  mode: 'exact' | 'atMost';
  variant: 'A' | 'B';
  weighted: boolean;
  maxWeight: number;
  duplicatePolicy: 'first-wins' | 'last-wins';
  votingStart: number;
  votingEnd: number;
  threshold: { t: number; n: number };
  keypers: Array<{ signingKey: string; url: string }>;
  eligibilityKey: string;
  resultPublisherKey: string;
  gatewayKeys: string[];
  adminKey: string;
  protocolVersion: string;
  selfSubmitFee: string;
}

export class GegConfigError extends Error {}

/**
 * The per-proposal ballot parameters, derived from mutable proposal fields.
 *
 * Weighted proposals encode proportional splits as integers summing to
 * `weightedBudget` (60 + 40 = 100); single-choice uses a budget of 1 and the
 * split degenerates to a unit vector. `mode: 'exact'` and `variant: 'A'` are the
 * only combination this deployment supports.
 */
export function deriveBallotParams(
  choices: string[],
  type: string | null | undefined,
  weightedBudget: number
): { numCandidates: number; budget: number; mode: 'exact'; variant: 'A' } {
  if (!Array.isArray(choices) || choices.length === 0) {
    throw new GegConfigError('proposal has no choices');
  }
  return {
    numCandidates: choices.length,
    budget: type === 'weighted' ? weightedBudget : 1,
    mode: 'exact',
    variant: 'A'
  };
}

export function parseCommitteeSnapshot(raw: unknown): TeCommitteeSnapshot {
  let snapshot: any = raw;
  if (typeof raw === 'string') {
    try {
      snapshot = JSON.parse(raw);
    } catch {
      throw new GegConfigError('te_geg_config is not valid JSON');
    }
  }
  if (!snapshot || typeof snapshot !== 'object') {
    throw new GegConfigError('proposal has no committee snapshot');
  }
  if (snapshot.v !== 1) {
    throw new GegConfigError(
      `unsupported committee snapshot version ${snapshot.v}`
    );
  }
  if (!Array.isArray(snapshot.keypers) || snapshot.keypers.length === 0) {
    throw new GegConfigError('committee snapshot has no keypers');
  }
  if (snapshot.keypers.length !== snapshot.thresholdN) {
    throw new GegConfigError(
      `committee snapshot lists ${snapshot.keypers.length} keypers but n = ${snapshot.thresholdN}`
    );
  }
  return snapshot as TeCommitteeSnapshot;
}

/**
 * Compose the wire config for one proposal.
 *
 * `currentEligibilityKey`, when supplied, is asserted against the frozen one. A
 * rotated eligibility key would otherwise invalidate every credential on older
 * proposals — excluding every ballot and producing a tally of zeros with nothing
 * to explain it — so this fails loudly instead.
 */
export function composeElectionConfig(args: {
  proposalId: string;
  choices: string[];
  type: string | null | undefined;
  snapshot: TeCommitteeSnapshot;
  currentEligibilityKey?: string;
}): GegElectionConfig {
  const { proposalId, choices, type, snapshot } = args;

  if (
    args.currentEligibilityKey &&
    args.currentEligibilityKey.toLowerCase() !==
      snapshot.eligibilityKey.toLowerCase()
  ) {
    throw new GegConfigError(
      'frozen eligibility key does not match the hub key in use; ' +
        'the key was rotated and credentials on this proposal can no longer verify'
    );
  }

  const params = deriveBallotParams(choices, type, snapshot.weightedBudget);

  return {
    electionId: proposalId,
    ...params,
    weighted: true,
    maxWeight: MAX_WEIGHT,
    duplicatePolicy: 'last-wins',
    votingStart: snapshot.votingStart,
    votingEnd: snapshot.votingEnd,
    threshold: { t: snapshot.thresholdT, n: snapshot.thresholdN },
    // The protocol calls a keyper's write-authorisation identity its signing
    // key; for this backend that is the member's Ethereum address.
    keypers: snapshot.keypers.map(k => ({
      signingKey: k.address.toLowerCase(),
      url: k.url
    })),
    eligibilityKey: snapshot.eligibilityKey.toLowerCase(),
    resultPublisherKey: snapshot.resultPublisherAddress.toLowerCase(),
    // Empty means ballot writes are unauthenticated at the data layer. Correct
    // here: ballots arrive through the sequencer's own signed-message pipeline,
    // never through this API.
    gatewayKeys: [],
    adminKey: snapshot.adminAddress.toLowerCase(),
    protocolVersion: PROTOCOL_VERSION,
    selfSubmitFee: '0'
  };
}
