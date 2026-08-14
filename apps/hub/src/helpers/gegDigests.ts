/**
 * Content-binding write digests for keyper submissions.
 *
 * A keyper signs the *content* of its write, not a generic request. That is what
 * lets the same signature be verified identically by any backend: this hub
 * recovers the signer and checks committee membership, while an on-chain backend
 * relays the same signature to a contract that `ecrecover`s the same digest. The
 * digests therefore mirror the Solidity byte-for-byte and are not ours to change —
 * they are the protocol's, and geg's Python computes them from the same definition.
 *
 *   dkg-result = keccak256("GEG-DKG-RESULT-v1" ‖ electionId ‖ pkElection
 *                          ‖ abi.encode(bytes[] committeePKs))
 *
 * Signed as an EIP-191 personal-sign message, so plain `ecrecover` and OpenZeppelin's
 * ECDSA helper agree on the recovered address.
 *
 * These replace the previous `SX-TE-*` digests. The difference is not cosmetic: the
 * old ones were an sx invention that only this hub understood, so a keyper had to be
 * built specifically for Snapshot. Adopting the protocol's digests is what allows an
 * unmodified keyper — one that knows nothing about Snapshot — to write here.
 *
 * ABI encoding is delegated to `@ethersproject/abi` rather than hand-rolled. The
 * offset arithmetic for a dynamic array of dynamic elements is easy to get subtly
 * wrong, and the aggregate digest that follows in a later phase encodes a nested
 * struct with several dynamic members. Parity with the Python side is pinned by
 * `test/unit/geg-digests.test.ts` against generated vectors.
 */

import { defaultAbiCoder } from '@ethersproject/abi';
import { getAddress } from '@ethersproject/address';
import { keccak256 } from '@ethersproject/keccak256';
import { verifyMessage } from '@ethersproject/wallet';

export const DKG_RESULT_DST = Buffer.from('GEG-DKG-RESULT-v1', 'utf8');

export class GegDigestError extends Error {}

/** Strict fixed-size hex decode. A wrong length here would silently shift the digest. */
export function decodeSized(
  value: unknown,
  label: string,
  size: number
): Buffer {
  if (typeof value !== 'string') {
    throw new GegDigestError(`${label}: not a string`);
  }
  const body =
    value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
  if (!/^[0-9a-fA-F]*$/.test(body)) {
    throw new GegDigestError(`${label}: not hex`);
  }
  if (body.length !== size * 2) {
    throw new GegDigestError(
      `${label}: expected ${size} bytes, got ${body.length / 2}`
    );
  }
  return Buffer.from(body, 'hex');
}

/**
 * The digest a keyper signs over its DKG result.
 *
 * `electionId` is the 32-byte election identifier — the proposal id. `pkElection`
 * is the 96-byte compressed joint public key, and `committeePKs` are the per-keyper
 * public keys in committee-index order.
 */
export function dkgResultDigest(args: {
  electionId: string;
  pkElection: string;
  committeePKs: string[];
}): Buffer {
  const electionId = decodeSized(args.electionId, 'electionId', 32);
  const pkElection = decodeSized(args.pkElection, 'pkElection', 96);
  if (!Array.isArray(args.committeePKs) || args.committeePKs.length === 0) {
    throw new GegDigestError('committeePKs: expected a non-empty array');
  }
  const committeePKs = args.committeePKs.map((pk, i) =>
    decodeSized(pk, `committeePKs[${i}]`, 96)
  );

  const encoded = Buffer.from(
    defaultAbiCoder.encode(['bytes[]'], [committeePKs]).slice(2),
    'hex'
  );
  const packed = Buffer.concat([
    DKG_RESULT_DST,
    electionId,
    pkElection,
    encoded
  ]);
  return Buffer.from(keccak256(packed).slice(2), 'hex');
}

/**
 * Recover the EIP-191 signer of a digest, checksummed.
 *
 * Returns `null` rather than throwing on a malformed signature, so a caller can
 * treat an unrecoverable signature exactly like a wrong one and answer with a
 * single uniform status — a prober learns nothing about which it was.
 */
export function recoverDigestSigner(
  digest: Buffer,
  signature: string
): string | null {
  try {
    return getAddress(verifyMessage(digest, signature));
  } catch {
    return null;
  }
}
