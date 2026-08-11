/**
 * The eligibility issuer: turns a stored vote's voting power into a signed
 * credential the keypers can verify.
 *
 * A weighted tally is only re-derivable from public data if the weight each
 * ballot was counted with is itself a public, verifiable artifact. Snapshot
 * records voting power in `votes.vp`, which is just a number in a database — an
 * auditor has no way to check that the weight used in the aggregate is the weight
 * that was recorded. Signing it fixes that: the credential binds
 * `(electionId, pseudonym, vk, weight, nonce)`, so anyone can confirm the tally
 * used the attested weight for the attested ballot.
 *
 * This adds **no new trust**. The sequencer is already authoritative for voting
 * power; what changes is that its claim becomes checkable. An auditor can verify
 * the binding, not the correctness of the voting power itself — that remains a
 * question about strategies and the score API, exactly as it is today.
 *
 * `nonce` is the vote's own timestamp. That is not a convenience: the protocol
 * ranks duplicate ballots by `(nonce, sequenceNumber)` and keeps the highest
 * under a last-wins policy, which is precisely Snapshot's "newer vote wins" rule.
 * A replayed older ballot loses on nonce.
 */

import {
  G1Point,
  initCurves,
  schnorrKeygen,
  signAttestation
} from '@snapshot-labs/private-vote-sdk';

export class GegAttestationError extends Error {}

const SK_RE = /^(0x)?[0-9a-fA-F]{64}$/;

let curvesReady: Promise<void> | null = null;
function ensureCurvesInit(): Promise<void> {
  if (!curvesReady) curvesReady = initCurves();
  return curvesReady;
}

interface Issuer {
  sk: bigint;
  vk: G1Point;
  /** Compressed 48-byte G1 public key, `0x`-prefixed lowercase hex. */
  publicKey: string;
}

let issuer: Issuer | null = null;

/** Test seam: drop the memoised issuer so a test can vary the configured key. */
export function resetIssuer(): void {
  issuer?.vk.destroyWasm();
  issuer = null;
}

/**
 * The configured issuer, memoised. The key point is held for the process
 * lifetime rather than rebuilt per request — it is a single WASM allocation and
 * every ballot read needs it.
 */
async function getIssuer(): Promise<Issuer> {
  if (issuer) return issuer;

  const raw = process.env.TE_ELIGIBILITY_PRIVATE_KEY;
  if (!raw?.trim()) {
    throw new GegAttestationError(
      'TE_ELIGIBILITY_PRIVATE_KEY is not configured'
    );
  }
  if (!SK_RE.test(raw.trim())) {
    throw new GegAttestationError(
      'TE_ELIGIBILITY_PRIVATE_KEY must be 32 bytes of hex'
    );
  }

  await ensureCurvesInit();
  const sk = BigInt(
    raw.trim().startsWith('0x') ? raw.trim() : `0x${raw.trim()}`
  );
  let keys;
  try {
    keys = schnorrKeygen(sk);
  } catch (err: any) {
    // schnorrKeygen rejects sk ≡ 0 mod Q, which would make every signature
    // trivially verifiable under the identity key.
    throw new GegAttestationError(
      `TE_ELIGIBILITY_PRIVATE_KEY is not a valid scalar: ${err?.message || err}`
    );
  }
  issuer = {
    sk: keys.sk,
    vk: keys.vk,
    publicKey: `0x${Buffer.from(keys.vk.toBytes()).toString('hex')}`
  };
  return issuer;
}

/** The public key to publish and to freeze into a proposal's config. */
export async function eligibilityPublicKey(): Promise<string> {
  return (await getIssuer()).publicKey;
}

export interface MintArgs {
  /** 32-byte election id, `0x`-prefixed. */
  electionId: string;
  /** 32-byte pseudonym from the ballot envelope, `0x`-prefixed. */
  pseudonym: string;
  /** 48-byte compressed G1 voter key from the ballot envelope, `0x`-prefixed. */
  vk: string;
  /** Integer weight, at least 1. */
  weight: bigint;
  /** Monotonic re-vote counter; the vote's timestamp. */
  nonce: bigint;
}

function bytes(hex: string, label: string, size: number): Uint8Array {
  const body = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (body.length !== size * 2 || !/^[0-9a-fA-F]*$/.test(body)) {
    throw new GegAttestationError(`${label}: expected ${size} bytes of hex`);
  }
  return new Uint8Array(Buffer.from(body, 'hex'));
}

/** Issue one credential. Returns the 80-byte signature as `0x` hex. */
export async function mintAttestation(args: MintArgs): Promise<string> {
  if (args.weight < 1n) {
    throw new GegAttestationError(`weight must be >= 1 (got ${args.weight})`);
  }
  if (args.nonce < 1n) {
    throw new GegAttestationError(`nonce must be >= 1 (got ${args.nonce})`);
  }
  const { sk, vk } = await getIssuer();
  const signature = signAttestation(sk, vk, {
    electionId: bytes(args.electionId, 'electionId', 32),
    pseudonym: bytes(args.pseudonym, 'pseudonym', 32),
    vk: bytes(args.vk, 'vk', 48),
    weight: args.weight,
    nonce: args.nonce
  });
  return `0x${Buffer.from(signature).toString('hex')}`;
}
