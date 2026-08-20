/**
 * Threshold-ElGamal vote-ingestion helpers.
 *
 * Validates a permanent-private (privacy='shutter-elgamal') ballot at
 * write time so we never persist a ciphertext that a later tally would
 * reject. The hub stores `proposal.choice` as the same JSON envelope the
 * voter submitted; this module decodes it into the SDK's
 * ``BallotInputs`` shape and runs ``verifyBallot`` against the
 * proposal's master public key.
 *
 * Pseudonym: ``keccak256(voter_address || proposal_id)``. Voter and the
 * sequencer agree on this construction; the sequencer recomputes it and
 * rejects any ballot that ships a different one (so a voter cannot
 * mis-link their ballot to someone else's proposal).
 */

import { arrayify } from '@ethersproject/bytes';
import { keccak256 } from '@ethersproject/keccak256';
import {
  BallotInputs,
  BallotVerifyParams,
  G2Point,
  initCurves,
  verifyBallot,
  VerifyResult
} from '@shutter-network/urban-verified-crypto';

let curvesReady: Promise<void> | null = null;

export function ensureCurvesInit(): Promise<void> {
  if (!curvesReady) curvesReady = initCurves();
  return curvesReady;
}

/** Wire envelope the voter sends as ``msg.payload.choice`` (a JSON string). */
export interface TeBallotEnvelope {
  electionId: string; // 0x-hex bytes32
  pseudonym: string; // 0x-hex bytes32
  vk: string; // 0x-hex 48-byte compressed G1 (voter Schnorr verification key)
  ciphertexts: Array<{ c1: string; c2: string }>; // each 0x-hex 96-byte compressed G2
  zkProof: string; // 0x-hex output of encodeBallotValidityProof
  voterSignature: string; // 0x-hex 80-byte encoded Schnorr sig
  wrAttestation?: string; // 0x-hex; not used by the snapshot ingest path
}

function hexToBytes(hex: string, label: string): Uint8Array {
  if (typeof hex !== 'string' || !/^0x[0-9a-fA-F]*$/.test(hex)) {
    throw new Error(`${label}: not a 0x hex string`);
  }
  if (hex.length % 2 !== 0) {
    throw new Error(`${label}: odd-length hex`);
  }
  return arrayify(hex);
}

export function expectedPseudonym(voter: string, proposalId: string): string {
  const voterBytes = arrayify(voter.toLowerCase());
  // proposalId in Snapshot is a 0x-prefixed bytes32-shaped string; we hash
  // its raw bytes after stripping the prefix. If a future proposal id
  // shape changes, the keyper-side tally code does the same construction.
  const idBytes = arrayify(proposalId);
  const buf = new Uint8Array(voterBytes.length + idBytes.length);
  buf.set(voterBytes, 0);
  buf.set(idBytes, voterBytes.length);
  return keccak256(buf);
}

export interface TeProposalView {
  id: string;
  te_config: BallotVerifyParams | null;
  te_mpk: string | null; // 0x-hex compressed G2 (96 bytes)
}

export async function verifyTeBallot(
  proposal: TeProposalView,
  voter: string,
  choiceJsonString: string
): Promise<VerifyResult> {
  if (!proposal.te_config) {
    return { ok: false, reason: 'proposal_missing_te_config' };
  }
  if (!proposal.te_mpk) {
    return { ok: false, reason: 'proposal_dkg_not_finalized' };
  }

  let envelope: TeBallotEnvelope;
  try {
    const raw = JSON.parse(choiceJsonString);
    if (!raw || typeof raw !== 'object') throw new Error('not object');
    envelope = raw as TeBallotEnvelope;
  } catch {
    return { ok: false, reason: 'choice_not_json_envelope' };
  }

  if (
    envelope.wrAttestation !== undefined &&
    envelope.wrAttestation !== null &&
    envelope.wrAttestation !== '0x' &&
    envelope.wrAttestation !== ''
  ) {
    return { ok: false, reason: 'wr_attestation_not_supported' };
  }

  // Pseudonym must equal keccak256(voter || proposalId). A mismatch is
  // either a malformed client or someone trying to attribute a ballot to
  // a different proposal — reject before doing the (expensive) zk verify.
  const expected = expectedPseudonym(voter, proposal.id);
  if (
    typeof envelope.pseudonym !== 'string' ||
    envelope.pseudonym.toLowerCase() !== expected.toLowerCase()
  ) {
    return { ok: false, reason: 'pseudonym_mismatch' };
  }

  let inputs: BallotInputs;
  let mpk: G2Point;
  try {
    inputs = {
      electionId: hexToBytes(envelope.electionId, 'electionId'),
      pseudonym: hexToBytes(envelope.pseudonym, 'pseudonym'),
      vk: hexToBytes(envelope.vk, 'vk'),
      ciphertexts: (envelope.ciphertexts || []).map(
        (c, i) =>
          [
            hexToBytes(c.c1, `ciphertexts[${i}].c1`),
            hexToBytes(c.c2, `ciphertexts[${i}].c2`)
          ] as [Uint8Array, Uint8Array]
      ),
      zkProof: hexToBytes(envelope.zkProof, 'zkProof'),
      voterSignature: hexToBytes(envelope.voterSignature, 'voterSignature'),
      wrAttestation: hexToBytes(envelope.wrAttestation || '0x', 'wrAttestation')
    };
    await ensureCurvesInit();
    mpk = G2Point.fromBytes(hexToBytes(proposal.te_mpk, 'te_mpk'));
  } catch (err: any) {
    return { ok: false, reason: `bad_envelope: ${err?.message || err}` };
  }

  // The WR slot is a constant ``() => true`` because the field it verifies is
  // required to be empty above. It can't carry the structured attestation because
  // the SDK's field is opaque bytes shaped for the legacy weightless scheme, no
  // room for weight or nonce. This is the end state, not a stub.
  try {
    return verifyBallot(inputs, proposal.te_config, mpk, () => true);
  } finally {
    mpk.destroyWasm();
  }
}

/**
 * A private ballot is counted by scaling its ciphertexts by an **integer**
 * weight — the protocol has no representation for a fractional one — so the hub
 * emits each ballot at `round(vp)` and skips anything that rounds to zero.
 * Voting power below 0.5 therefore contributes nothing to a private tally, where
 * the same figure would count normally on a public proposal.
 * Refusing such a vote at ingest is better than accepting one the tally will
 * drop.
 */
export function isDustVotingPower(vp: number): boolean {
  return !Number.isFinite(vp) || Math.round(vp) < 1;
}

export function isWithinGegVotingWindow(
  t: number,
  votingStart: number,
  votingEnd: number
): boolean {
  return votingStart <= t && t < votingEnd;
}
