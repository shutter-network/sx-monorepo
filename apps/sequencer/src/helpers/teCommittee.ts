/**
 * The threshold committee snapshot frozen onto a private proposal at creation.
 *
 * Proposal creation is the registration event for the threshold protocol — the
 * one moment a proposal's committee, threshold, and role keys are decided — so
 * this is the single config write in sx. Everything downstream reads
 * `proposals.te_geg_config` and never mutates it.
 *
 * Freezing matters because the committee is configured fleet-wide in env. Without
 * a per-proposal snapshot, changing `TE_KEYPERS` or `TE_THRESHOLD_T` would
 * retroactively rewrite the config of proposals that had already run their key
 * generation against the *old* committee — and a keyper resolves its own index by
 * matching its signing key against that list, so the tally would break with no
 * obvious cause.
 *
 * What is deliberately **not** here: `numCandidates`, `budget`, `mode`, and
 * `variant`. Those derive from `choices` and `type`, which `update-proposal` lets
 * an author edit until `start`, so a frozen copy would go stale. The hub derives
 * them live on every read; that is safe because the same endpoint refuses edits
 * once voting opens, making them constant for the whole voting window.
 *
 * This snapshot is also deliberately **sx-shaped, not the protocol wire format**.
 * The hub is the only process that speaks the protocol's JSON (it already links
 * the crypto SDK), so it owns that mapping. Keeping wire-format knowledge in one
 * place is what stops an enum-value or key-name drift — which surfaces as every
 * read failing to decode — from being possible in two places at once.
 *
 * See docs/private-voting/geg-integration-plan.md §5.
 */

import { keccak256 } from '@ethersproject/keccak256';
import { toUtf8Bytes } from '@ethersproject/strings';

/**
 * EIP-55 checksum an already-validated lowercase address.
 *
 * Written out rather than pulled from `@ethersproject/address` because the
 * sequencer does not depend on that package, and one small well-understood
 * function is a better trade than a new dependency. Storing the checksummed form
 * matters: the hub's existing write-authorisation path compares committee
 * addresses against `getAddress()` output, so a lowercase copy would silently
 * fail to match.
 */
function toChecksumAddress(address: string): string {
  const lower = address.toLowerCase().slice(2);
  const hash = keccak256(toUtf8Bytes(lower)).slice(2);
  let out = '0x';
  for (let i = 0; i < lower.length; i++) {
    out += parseInt(hash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  }
  return out;
}

/** One committee member: the address that signs its writes, and where to reach it. */
export interface TeKeyper {
  address: string;
  url: string;
}

/** The frozen snapshot, stored verbatim as `proposals.te_geg_config`. */
export interface TeCommitteeSnapshot {
  /** Schema version of this snapshot, so a later shape change is detectable. */
  v: 1;
  keypers: TeKeyper[];
  /** Reconstruction threshold: any `t + 1` keypers can decrypt. */
  thresholdT: number;
  /** Committee size. Always `keypers.length`; stored so reads need no derivation. */
  thresholdN: number;
  /** Compressed G1 eligibility public key, fetched from the hub at creation. */
  eligibilityKey: string;
  /** Address allowed to publish the result and mark a tally stalled. */
  resultPublisherAddress: string;
  /** Address allowed to clear a stalled tally. */
  adminAddress: string;
  /** Voting window, mirrored from the proposal so the config is self-contained. */
  votingStart: number;
  votingEnd: number;
  /**
   * Denominator for weighted vote splits. Frozen because it is a deployment
   * choice, unlike the per-proposal `budget` the hub derives from `type`.
   */
  weightedBudget: number;
}

export class TeConfigError extends Error {}

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const G1_KEY_RE = /^0x[0-9a-fA-F]{96}$/;

/**
 * Parse `TE_KEYPERS`: a comma-separated list of `address@url`.
 *
 * Addresses are configured explicitly and never discovered from a keyper's own
 * `/status` response. That is the whole point: discovery let a network attacker
 * substitute an address mid-ceremony and have the committee verify signatures
 * against it (flaw F4 in docs/private-voting/architecture.md). A configured list
 * is the authority.
 */
export function parseKeypers(raw: string | undefined): TeKeyper[] {
  if (!raw?.trim()) return [];
  return raw
    .split(',')
    .map(entry => entry.trim())
    .filter(Boolean)
    .map(entry => {
      const at = entry.indexOf('@');
      if (at === -1) {
        throw new TeConfigError(
          `TE_KEYPERS entry "${entry}" must be "address@url"`
        );
      }
      const address = entry.slice(0, at).trim();
      const url = entry
        .slice(at + 1)
        .trim()
        .replace(/\/+$/, '');
      if (!ADDRESS_RE.test(address)) {
        throw new TeConfigError(
          `TE_KEYPERS entry "${entry}" has a malformed address`
        );
      }
      if (!url) {
        throw new TeConfigError(`TE_KEYPERS entry "${entry}" has an empty url`);
      }
      return { address: toChecksumAddress(address), url };
    });
}

export interface TeEnv {
  keypers: string | undefined;
  thresholdT: string | undefined;
  weightedBudget: string | undefined;
  adminAddress: string | undefined;
  resultPublisherAddress: string | undefined;
}

export function readTeEnv(env: NodeJS.ProcessEnv = process.env): TeEnv {
  return {
    keypers: env.TE_KEYPERS,
    thresholdT: env.TE_THRESHOLD_T,
    weightedBudget: env.TE_WEIGHTED_BUDGET,
    adminAddress: env.TE_ADMIN_ADDRESS,
    resultPublisherAddress: env.TE_RESULT_PUBLISHER_ADDRESS
  };
}

/** True when the deployment is configured to accept private proposals at all. */
export function isTeConfigured(env: TeEnv = readTeEnv()): boolean {
  return Boolean(env.keypers?.trim());
}

function requireAddress(value: string | undefined, name: string): string {
  if (!value?.trim()) throw new TeConfigError(`${name} is required`);
  const v = value.trim();
  if (!ADDRESS_RE.test(v)) throw new TeConfigError(`${name} is not an address`);
  return toChecksumAddress(v);
}

function requireInt(
  value: string | undefined,
  name: string,
  fallback?: number
): number {
  if (value === undefined || value.trim() === '') {
    if (fallback !== undefined) return fallback;
    throw new TeConfigError(`${name} is required`);
  }
  const n = Number(value);
  if (!Number.isInteger(n))
    throw new TeConfigError(`${name} must be an integer`);
  return n;
}

/**
 * Build the snapshot for one proposal, rejecting a misconfigured committee.
 *
 * Every check here mirrors a constraint the protocol's own config type enforces.
 * They run at creation so a bad committee fails in front of the author with a
 * readable message, rather than silently producing a proposal whose key
 * generation can never complete — which would otherwise surface minutes later
 * as an unexplained terminal failure.
 */
export function buildCommitteeSnapshot(args: {
  env?: TeEnv;
  eligibilityKey: string;
  votingStart: number;
  votingEnd: number;
}): TeCommitteeSnapshot {
  const env = args.env ?? readTeEnv();

  const keypers = parseKeypers(env.keypers);
  if (keypers.length === 0) {
    throw new TeConfigError(
      'TE_KEYPERS is not configured; this deployment cannot host private proposals'
    );
  }

  const seen = new Set<string>();
  for (const k of keypers) {
    const key = k.address.toLowerCase();
    if (seen.has(key)) {
      throw new TeConfigError(`TE_KEYPERS lists ${k.address} more than once`);
    }
    seen.add(key);
  }

  const thresholdN = keypers.length;
  const thresholdT = requireInt(env.thresholdT, 'TE_THRESHOLD_T', 1);
  // t + 1 keypers must be able to decrypt, and t + 1 must be reachable, so
  // 0 <= t < n. t = 0 is a degenerate single-keyper committee, still valid.
  if (thresholdT < 0 || thresholdT >= thresholdN) {
    throw new TeConfigError(
      `TE_THRESHOLD_T (${thresholdT}) must satisfy 0 <= t < n, with n = ${thresholdN}`
    );
  }

  const weightedBudget = requireInt(
    env.weightedBudget,
    'TE_WEIGHTED_BUDGET',
    100
  );
  if (weightedBudget < 1) {
    throw new TeConfigError('TE_WEIGHTED_BUDGET must be >= 1');
  }

  if (!G1_KEY_RE.test(args.eligibilityKey)) {
    throw new TeConfigError(
      'eligibility key must be a 0x-prefixed 48-byte compressed G1 point'
    );
  }

  if (!(args.votingEnd > args.votingStart)) {
    throw new TeConfigError(
      `votingEnd (${args.votingEnd}) must be after votingStart (${args.votingStart})`
    );
  }

  return {
    v: 1,
    keypers,
    thresholdT,
    thresholdN,
    eligibilityKey: args.eligibilityKey.toLowerCase(),
    resultPublisherAddress: requireAddress(
      env.resultPublisherAddress,
      'TE_RESULT_PUBLISHER_ADDRESS'
    ),
    adminAddress: requireAddress(env.adminAddress, 'TE_ADMIN_ADDRESS'),
    votingStart: args.votingStart,
    votingEnd: args.votingEnd,
    weightedBudget
  };
}

/**
 * The columns to write alongside a private proposal.
 *
 * `te_geg_config` is the authority. The four `te_threshold_*` / `te_keyper_*`
 * columns are denormalised copies for readers that already exist — the UI's
 * committee card, and the hub's write-authorisation path which indexes
 * `te_keyper_addresses[keyper_index - 1]`. Never edit those to fix a
 * disagreement; regenerate them from the snapshot.
 */
export function committeeColumns(snapshot: TeCommitteeSnapshot): {
  te_geg_config: string;
  te_threshold_t: number;
  te_threshold_n: number;
  te_keyper_urls: string;
  te_keyper_addresses: string;
} {
  return {
    te_geg_config: JSON.stringify(snapshot),
    te_threshold_t: snapshot.thresholdT,
    te_threshold_n: snapshot.thresholdN,
    te_keyper_urls: JSON.stringify(snapshot.keypers.map(k => k.url)),
    te_keyper_addresses: JSON.stringify(snapshot.keypers.map(k => k.address))
  };
}
