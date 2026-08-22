import { arrayify } from '@ethersproject/bytes';
import { keccak256 } from '@ethersproject/keccak256';

/** Distinct from the ballot and attestation labels, so a signature over one can
 * never be replayed as a signature over another. */
const BINDING_LABEL = 'SHUTTER-VOTE-BINDING-v1';
const ATTESTATION_LABEL = 'SHUTTER-VOTE-ATTEST-v1';

/** Bound as a scalar so a LEGACY credential and a V1 one over otherwise
 * identical fields cannot produce the same binding. */
const SCHEME_CODES: Record<string, bigint> = {
  ATTESTATION_V1: 1n,
  ATTESTATION_LEGACY: 2n
};

const textEncoder = new TextEncoder();

function u32BE(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** One length-prefixed transcript entry; the prefixes are what make
 * concatenation injective. */
function field(tag: string, value: Uint8Array): Uint8Array {
  const t = textEncoder.encode(tag);
  return concatBytes([u32BE(t.length), t, u32BE(value.length), value]);
}

function scalar32BE(value: bigint): Uint8Array {
  const b = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}

const digest = (preimage: Uint8Array) => arrayify(keccak256(preimage));

export interface BallotCredential {
  scheme: string;
  electionId: string;
  pseudonym: string;
  vk: string;
  weight: number;
  nonce: number;
  signature: string;
}

/** The credential's own signed digest — the same one the issuer signed. */
export function credentialDigest(att: BallotCredential): Uint8Array {
  const electionId = arrayify(att.electionId);
  const pseudonym = arrayify(att.pseudonym);
  const vk = arrayify(att.vk);
  const scheme = att.scheme || 'ATTESTATION_V1';

  if (scheme === 'ATTESTATION_LEGACY') {
    // Weightless, and deliberately not the V1 transcript: a bare keccak
    // concatenation with no domain separator, kept only for interop.
    return digest(concatBytes([electionId, pseudonym, vk]));
  }
  if (scheme !== 'ATTESTATION_V1') {
    throw new Error(`unknown attestation scheme: ${scheme}`);
  }
  return digest(
    concatBytes([
      textEncoder.encode(ATTESTATION_LABEL), // the label seeds the log unprefixed
      field('attest:electionId', electionId),
      field('attest:pseudonym', pseudonym),
      field('attest:vk', vk),
      field('attest:weight', scalar32BE(BigInt(att.weight))),
      field('attest:nonce', scalar32BE(BigInt(att.nonce)))
    ])
  );
}

/** The keccak256 digest the voter signs to bind one ballot to one credential. */
export function bindingMessage(args: {
  electionId: string;
  pseudonym: string;
  vk: string;
  /** `keccak256(canonicalBallotMessage(...))`. */
  ballotDigest: string;
  attestation: BallotCredential;
}): Uint8Array {
  const scheme = args.attestation.scheme || 'ATTESTATION_V1';
  const code = SCHEME_CODES[scheme];
  if (code === undefined) {
    throw new Error(`unknown attestation scheme: ${scheme}`);
  }
  const eligSig = arrayify(args.attestation.signature);
  if (eligSig.length === 0) {
    throw new Error('eligibilitySignature must not be empty');
  }

  return digest(
    concatBytes([
      textEncoder.encode(BINDING_LABEL),
      field('bind:electionId', arrayify(args.electionId)),
      field('bind:pseudonym', arrayify(args.pseudonym)),
      field('bind:vk', arrayify(args.vk)),
      field('bind:ballot', arrayify(args.ballotDigest)),
      field('bind:scheme', scalar32BE(code)),
      field('bind:attestation', credentialDigest(args.attestation)),
      // The issuer's signature too, so the voter commits to the exact credential
      // instance rather than to fields another one could also satisfy.
      field('bind:eligSig', eligSig)
    ])
  );
}

export interface IssuedCredentialResponse {
  attestation: BallotCredential;
  /** Voting power before the cap, so the UI can show what the clamp cost. */
  votingPower: number;
  maxWeight: number;
}

/**
 * Ask the sequencer for a credential for this ballot key.
 *
 * No signature: the request names the voter and proves nothing, because a
 * credential is worthless to anyone else. Ingest derives the pseudonym from the
 * EIP-712-authenticated voter and refuses any envelope that disagrees, so a
 * credential naming this address can only be spent by a vote this address signs.
 * Requiring a `personal_sign` here was tried and removed — it added a second
 * wallet prompt to every private vote and bought no integrity the pseudonym check
 * does not already give.
 *
 * The voter cannot vote at all if this fails — a real availability change from
 * minting at ingest, and the reason the error is surfaced verbatim rather than
 * folded into a generic failure.
 */
export async function requestBallotCredential(args: {
  sequencerUrl: string;
  space: string;
  proposalId: string;
  vk: string;
  voter: string;
}): Promise<IssuedCredentialResponse> {
  const res = await fetch(
    `${args.sequencerUrl.replace(/\/$/, '')}/te_attestation`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        space: args.space,
        proposal: args.proposalId,
        vk: args.vk,
        voter: args.voter
      })
    }
  );

  if (!res.ok) {
    const detail = await res.text();
    throw new Error(
      `could not obtain a ballot credential (${res.status}): ${detail}`
    );
  }
  return (await res.json()) as IssuedCredentialResponse;
}
