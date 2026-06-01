/**
 * Phase 8 — client-side tally audit.
 *
 * Calls the hub's public GET endpoint for decryption shares + the
 * proposal's TE configuration, then runs the SDK's ``recoverTally``
 * locally so that any auditor can independently confirm the published
 * scores. Every share's DLEQ proof is verified inside ``recoverTally``;
 * the wrapper here is essentially "fetch the public bytes and feed
 * them to the SDK in the same shape the sequencer used".
 *
 * Returned value: the per-candidate integer tallies. Comparison to the
 * proposal's published scores is done by the calling component so that
 * the UI can highlight any mismatch in the right place.
 */
import { arrayify } from '@ethersproject/bytes';
import {
  G2Point,
  PartialDecryption,
  Transcript,
  decodeDLEQ,
  recoverTally,
  type Ciphertext
} from '@snapshot-labs/private-vote-sdk';
import { ensureCurvesInit } from './teBallot';

const DECRYPT_TRANSCRIPT_LABEL = 'SHUTTER-VOTE-DECRYPT-v1';

function u16BE(n: number): Uint8Array {
  const b = new Uint8Array(2);
  b[0] = (n >> 8) & 0xff;
  b[1] = n & 0xff;
  return b;
}

export interface AuditPayload {
  te_mpk: string;
  te_committee_pks: string[];
  te_threshold_t: number;
  te_threshold_n: number;
  te_keyper_addresses: string[];
  aggregate: {
    election_id: string;
    num_candidates: number;
    ciphertexts: Array<{ c1: string; c2: string }>;
  };
  shares: Array<{
    keyper_index: number;
    candidate: number;
    sigma: string;
    proof_e: string;
    proof_z: string;
  }>;
}

export interface VerifyResult {
  tallies: bigint[];
  matchesPublished: boolean | null;
  shareCount: number;
  thresholdMet: boolean;
}

/**
 * Pull the public audit payload from the hub. The base URL must end at
 * the ``/api`` prefix (i.e. the same prefix the sequencer's vote ingest
 * uses); the function appends the proposal-specific path.
 */
export async function fetchAuditPayload(
  apiBaseUrl: string,
  proposalId: string
): Promise<AuditPayload> {
  const url = `${apiBaseUrl.replace(/\/$/, '')}/proposal/${encodeURIComponent(
    proposalId
  )}/te_decryption_shares`;
  const r = await fetch(url, { credentials: 'omit' });
  if (!r.ok) throw new Error(`hub ${r.status}: ${await r.text()}`);
  return (await r.json()) as AuditPayload;
}

/**
 * Run ``recoverTally`` against a hub-supplied audit payload.
 *
 * Throws synchronously on shape mismatches (missing aggregate, fewer
 * than ``t+1`` shares for some candidate, malformed hex). Otherwise
 * returns the recovered tallies and an optional comparison flag if
 * ``publishedScores`` is supplied.
 */
export async function verifyTally(
  proposalId: string,
  payload: AuditPayload,
  publishedScores?: number[]
): Promise<VerifyResult> {
  await ensureCurvesInit();

  const { aggregate, te_committee_pks, te_threshold_t, shares } = payload;
  const numCandidates = aggregate.num_candidates;
  if (numCandidates !== aggregate.ciphertexts.length) {
    throw new Error(
      `aggregate.num_candidates=${numCandidates} disagrees with ciphertexts.length=${aggregate.ciphertexts.length}`
    );
  }

  const ctSums: Ciphertext[] = aggregate.ciphertexts.map(({ c1, c2 }) => [
    arrayify(c1),
    arrayify(c2)
  ]);

  const committeePKs = te_committee_pks.map(hex => G2Point.fromBytes(arrayify(hex)));

  // Group shares per candidate (0-indexed). Each share's DLEQ bytes
  // are the concatenation of proof_e || proof_z (32+32). The SDK
  // ``decodeDLEQ`` accepts that exact layout.
  const sharesPerCandidate: PartialDecryption[][] = Array.from(
    { length: numCandidates },
    () => []
  );
  for (const s of shares) {
    if (s.candidate < 0 || s.candidate >= numCandidates) continue;
    const sigma = G2Point.fromBytes(arrayify(s.sigma));
    const proofBytes = new Uint8Array(64);
    proofBytes.set(arrayify(s.proof_e), 0);
    proofBytes.set(arrayify(s.proof_z), 32);
    sharesPerCandidate[s.candidate].push({
      keyperIndex: s.keyper_index,
      sigma,
      proof: decodeDLEQ(proofBytes)
    });
  }
  const thresholdMet = sharesPerCandidate.every(
    arr => arr.length >= te_threshold_t + 1
  );
  if (!thresholdMet) {
    throw new Error(
      `not enough decryption shares per candidate (need t+1=${te_threshold_t + 1})`
    );
  }

  const electionIdBytes = arrayify(proposalId);
  // BSGS upper bound: total VP across all ballots is bounded above by
  // sum of published scores when published scores are available.
  // Otherwise fall back to a generous default of 1<<40 so the audit
  // can still run (the BSGS table size is `sqrt(upperBound)`).
  const sumPublished = (publishedScores || []).reduce(
    (s, n) => s + BigInt(Math.floor(n)),
    0n
  );
  const upperBound = sumPublished > 0n ? sumPublished + 1n : 1n << 40n;

  const tallies = recoverTally({
    ctSums,
    sharesPerCandidate,
    threshold: te_threshold_t,
    committeePKs,
    upperBound,
    transcriptFor: (j: number) => {
      const t = new Transcript(DECRYPT_TRANSCRIPT_LABEL);
      t.append('electionId', electionIdBytes);
      t.append('candidate', u16BE(j));
      return t;
    }
  });

  let matchesPublished: boolean | null = null;
  if (publishedScores) {
    matchesPublished =
      publishedScores.length === tallies.length &&
      tallies.every((v, i) => v === BigInt(Math.floor(publishedScores[i])));
  }

  return {
    tallies,
    matchesPublished,
    shareCount: shares.length,
    thresholdMet
  };
}
