import { keccak256 } from '@ethersproject/keccak256';
import {
  canonicalBallotMessage,
  G1Point,
  schnorrVerify
} from '@shutter-network/urban-verified-crypto';
import { attestationMessage, GegAttestationError } from './gegAttestation';
import { ensureCurvesInit } from './te';

/** Distinct from the ballot and attestation labels, so a signature over one can
 * never be presented as a signature over another. */
const BINDING_LABEL = 'SHUTTER-VOTE-BINDING-v1';

/** Bound as a scalar so a LEGACY credential and a V1 one over otherwise identical
 * fields cannot produce the same binding. */
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
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

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

export function hexToBytes(
  hex: string,
  label: string,
  size?: number
): Uint8Array {
  const body =
    typeof hex === 'string' && hex.startsWith('0x') ? hex.slice(2) : hex;
  if (
    typeof body !== 'string' ||
    !/^[0-9a-fA-F]*$/.test(body) ||
    body.length % 2 !== 0 ||
    (size !== undefined && body.length !== size * 2)
  ) {
    throw new GegAttestationError(
      size === undefined
        ? `${label}: expected hex`
        : `${label}: expected ${size} bytes of hex`
    );
  }
  return new Uint8Array(Buffer.from(body, 'hex'));
}

export interface BindingCredential {
  scheme?: string;
  electionId: string;
  pseudonym: string;
  vk: string;
  weight: number | string | bigint;
  nonce: number | string | bigint;
  signature: string;
}

/** The credential's own signed digest — the same one the issuer signed. */
export function credentialDigest(att: BindingCredential): Uint8Array {
  const scheme = att.scheme ?? 'ATTESTATION_V1';
  const electionId = hexToBytes(att.electionId, 'electionId', 32);
  const pseudonym = hexToBytes(att.pseudonym, 'pseudonym', 32);
  const vk = hexToBytes(att.vk, 'vk', 48);

  if (scheme === 'ATTESTATION_LEGACY') {
    // Weightless, and deliberately *not* the V1 transcript: a bare keccak
    // concatenation with no domain separator, kept only for interop.
    return new Uint8Array(
      Buffer.from(
        keccak256(concatBytes([electionId, pseudonym, vk])).slice(2),
        'hex'
      )
    );
  }
  if (scheme !== 'ATTESTATION_V1') {
    throw new GegAttestationError(`unknown attestation scheme: ${scheme}`);
  }
  return attestationMessage(
    electionId,
    pseudonym,
    vk,
    BigInt(att.weight),
    BigInt(att.nonce)
  );
}

export interface BindingMessageArgs {
  /** `0x`-prefixed 32-byte election id. */
  electionId: string;
  /** `0x`-prefixed 32-byte pseudonym. */
  pseudonym: string;
  /** `0x`-prefixed 48-byte compressed G1 voter key. */
  vk: string;
  /** `keccak256(canonicalBallotMessage(...))`, `0x`-prefixed 32 bytes. */
  ballotDigest: string;
  attestation: BindingCredential;
}

/** The keccak256 digest the voter signs to bind one ballot to one credential. */
export function bindingMessage(args: BindingMessageArgs): Uint8Array {
  const scheme = args.attestation.scheme ?? 'ATTESTATION_V1';
  const code = SCHEME_CODES[scheme];
  if (code === undefined) {
    throw new GegAttestationError(`unknown attestation scheme: ${scheme}`);
  }
  const eligSig = hexToBytes(
    args.attestation.signature,
    'eligibilitySignature'
  );
  if (eligSig.length === 0) {
    throw new GegAttestationError('eligibilitySignature must not be empty');
  }

  const preimage = concatBytes([
    textEncoder.encode(BINDING_LABEL), // the label seeds the log unprefixed
    field('bind:electionId', hexToBytes(args.electionId, 'electionId', 32)),
    field('bind:pseudonym', hexToBytes(args.pseudonym, 'pseudonym', 32)),
    field('bind:vk', hexToBytes(args.vk, 'vk', 48)),
    field('bind:ballot', hexToBytes(args.ballotDigest, 'ballotDigest', 32)),
    field('bind:scheme', scalar32BE(code)),
    field('bind:attestation', credentialDigest(args.attestation)),
    // The issuer's signature too, so the voter commits to the exact credential
    // instance rather than to fields a differently-signed one could also satisfy.
    field('bind:eligSig', eligSig)
  ]);
  return new Uint8Array(Buffer.from(keccak256(preimage).slice(2), 'hex'));
}

export interface VerifyBindingArgs {
  /** The ballot envelope as submitted: pseudonym, vk, ciphertexts, zkProof. */
  envelope: any;
  attestation: BindingCredential;
  /** 80-byte Schnorr signature, `0x` hex. */
  signature: string;
}

/**
 * Verify the voter's binding signature over (ballot, credential).
 *
 * Returns `false` rather than throwing on anything malformed, so a caller can
 * treat one uniform answer as "this ballot is not bound" — the same discipline
 * `verifyAttestation` follows, and the reason a mangled signature cannot become
 * an unhandled error on the ingest path.
 */
export async function verifyBallotBinding(
  args: VerifyBindingArgs
): Promise<boolean> {
  try {
    // `G1Point.fromBytes` touches the BLST WASM heap, which has to be up first.
    // Idempotent, and already paid for by ballot verification on this path.
    await ensureCurvesInit();
    const { envelope, attestation, signature } = args;
    const ciphertexts = (envelope?.ciphertexts ?? []).map((ct: any) => [
      hexToBytes(ct?.c1, 'c1', 96),
      hexToBytes(ct?.c2, 'c2', 96)
    ]) as [Uint8Array, Uint8Array][];
    if (!ciphertexts.length) return false;

    const ballotDigest = keccak256(
      canonicalBallotMessage({
        electionId: hexToBytes(envelope.electionId, 'electionId', 32),
        pseudonym: hexToBytes(envelope.pseudonym, 'pseudonym', 32),
        ciphertexts,
        zkProof: hexToBytes(envelope.zkProof, 'zkProof')
      })
    );

    const message = bindingMessage({
      electionId: envelope.electionId,
      pseudonym: envelope.pseudonym,
      vk: envelope.vk,
      ballotDigest,
      attestation
    });

    const sig = hexToBytes(signature, 'voterAttestationSignature', 80);
    // The released SDK exports `encodeSchnorr` but no decoder, so the 80-byte
    // wire form is split here: R (48, compressed G1) then s (32, big-endian).
    const R = G1Point.fromBytes(sig.slice(0, 48));
    const sScalar = BigInt(`0x${Buffer.from(sig.slice(48)).toString('hex')}`);
    const vk = G1Point.fromBytes(hexToBytes(envelope.vk, 'vk', 48));
    try {
      return schnorrVerify(vk, message, { R, s: sScalar });
    } finally {
      R.destroyWasm();
      vk.destroyWasm();
    }
  } catch {
    return false;
  }
}
