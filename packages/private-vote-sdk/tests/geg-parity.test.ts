/**
 * GATE 0 — geg parity.
 *
 * This package is a vendored fork of `@shutter-network/urban-verified-crypto`
 * (upstream `17dcaf5`). The `generalised-el-gamal` (`geg`) Python implementation
 * proves byte-parity against that same upstream. The Snapshot integration makes
 * both run against one wire format at once — geg's keypers aggregate and decrypt
 * the very ballots this SDK builds and verifies — so "the fork has not diverged"
 * stops being a nicety and becomes a correctness precondition.
 *
 * This test is the proof. It replays geg's **own canonical vector corpus**
 * (`tests/vectors-geg/`, a checked-in copy — see PROVENANCE.md) through this
 * fork and asserts every expectation holds. If it fails, the fork and geg
 * disagree about the protocol and no integration work should proceed.
 *
 * Coverage is asserted, not assumed: the final test fails if any vector file on
 * disk went unchecked, so a vector geg adds later cannot be silently skipped.
 *
 * Three things go beyond the shared eight-category runner:
 *
 *   - `attestation/` — `ATTESTATION_V1`, the credential hub mints in TypeScript
 *     and geg verifies in Python. The riskiest new surface in the integration.
 *   - `ballot/*_known` — a *construction* vector with pinned randomness, so the
 *     canonical Schnorr preimage can be compared byte-for-byte.
 *   - `flow/` — a complete election: 5 ballots (one duplicate, one with a bad
 *     signature) → weighted aggregate over the admitted set → t+1 shares →
 *     Lagrange + BSGS → published totals. This exercises the exact pipeline the
 *     integration splits across hub, the keypers, and the coordinator.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  addCt,
  Attestation,
  canonicalBallotMessage,
  Ciphertext,
  G2Point,
  initCurves,
  recoverTally,
  scalarMulCt,
  Transcript,
  verifyAttestation,
  verifyBallot
} from '../src';
import {
  listAllVectorFiles,
  loadCategory,
  registerVectorSuite
} from './lib/vectorSuite';
import { decodeDLEQ } from '../src/contract/codec';

const GEG_VECTORS_DIR = join(__dirname, 'vectors-geg');

beforeAll(async () => {
  await initCurves();
});

/**
 * Strict hex decode. geg emits bare hex in the primitive vectors and
 * `0x`-prefixed hex in the flow envelopes, so both are accepted — but anything
 * else throws rather than silently decoding to a short buffer, which is what
 * `Buffer.from(s, 'hex')` does on its own and how a parity test quietly turns
 * into a no-op.
 */
function hex(s: unknown, label: string): Uint8Array {
  if (typeof s !== 'string') throw new Error(`${label}: not a string`);
  const body = s.startsWith('0x') || s.startsWith('0X') ? s.slice(2) : s;
  if (body.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(body)) {
    throw new Error(`${label}: not hex (${s.slice(0, 24)}…)`);
  }
  return new Uint8Array(Buffer.from(body, 'hex'));
}

function u16BE(n: number): Uint8Array {
  return new Uint8Array([(n >>> 8) & 0xff, n & 0xff]);
}

function readVector<T>(relPath: string): T {
  return JSON.parse(readFileSync(join(GEG_VECTORS_DIR, relPath), 'utf8')) as T;
}

// ---------------------------------------------------------------------------

type AttestationVector = {
  name: string;
  inputs: {
    eligibilityKey: string;
    electionId: string;
    pseudonym: string;
    vk: string;
    weight: number;
    nonce: number;
    scheme: 'ATTESTATION_V1' | 'ATTESTATION_LEGACY';
    signature: string;
    maxWeight: number;
  };
  expected: { verify: boolean };
};

type FlowVector = {
  config: {
    electionId: string;
    numCandidates: number;
    budget: number;
    mode: 'exact' | 'atMost';
    variant: 'A' | 'B';
    maxWeight: number;
    threshold: { t: number; n: number };
    eligibilityKey: string;
  };
  finalizedKey: { pkElection: string; committeePKs: string[] };
  ballots: Array<{
    electionId: string;
    pseudonym: string;
    vk: string;
    ciphertexts: Array<{ c1: string; c2: string }>;
    zkProof: string;
    voterSignature: string;
    attestation: {
      scheme: 'ATTESTATION_V1' | 'ATTESTATION_LEGACY';
      electionId: string;
      pseudonym: string;
      vk: string;
      weight: number;
      nonce: number;
      signature: string;
    };
  }>;
  aggregate: {
    aggregates: Array<{ c1: string; c2: string }>;
    admitted: number[];
    exclusions: Array<{ sequenceNumber: number; reason: string }>;
    totalAdmittedWeight: number;
  };
  shares: Array<{
    keyperIndex: number;
    entries: Array<{ sigma: string; proof: string }>;
  }>;
  result: { totals: number[]; keyperIndices: number[]; bsgsBound: number };
};

/** Exclusion reasons that mean the ballot's own crypto is invalid. */
const CRYPTO_FAILURE_REASONS = new Set([
  'INVALID_PROOF',
  'INVALID_SIGNATURE',
  'MALFORMED'
]);

// ---------------------------------------------------------------------------

describe('gate 0 — geg canonical vectors verify under this fork', () => {
  const handled = registerVectorSuite(GEG_VECTORS_DIR);

  describe('attestation/', () => {
    for (const { name, file, vec } of loadCategory<AttestationVector>(
      GEG_VECTORS_DIR,
      'attestation'
    )) {
      handled.add(file);
      it(name, () => {
        const i = vec.inputs;
        const attestation: Attestation = {
          electionId: hex(i.electionId, 'electionId'),
          pseudonym: hex(i.pseudonym, 'pseudonym'),
          vk: hex(i.vk, 'vk'),
          weight: BigInt(i.weight),
          nonce: BigInt(i.nonce),
          signature: hex(i.signature, 'signature'),
          scheme: i.scheme
        };
        const ok = verifyAttestation(
          hex(i.eligibilityKey, 'eligibilityKey'),
          attestation,
          {
            electionId: attestation.electionId,
            maxWeight: BigInt(i.maxWeight)
          }
        );
        expect(ok).toBe(vec.expected.verify);
      });
    }
  });

  describe('ballot/ construction vector (pinned randomness)', () => {
    const FILE = 'ballot/ballot_variantA_exact_known.json';
    handled.add(FILE);
    type KnownBallot = {
      inputs: {
        electionId: string;
        pseudonym: string;
        vk: string;
        mpk: string;
        params: {
          numCandidates: number;
          budget: number;
          mode: 'exact' | 'atMost';
          variant: 'A' | 'B';
        };
      };
      outputs: {
        ciphertexts: string[][];
        zkProof: string;
        voterSignature: string;
        canonical_preimage: string;
      };
      expected: { verifyBallot: boolean; reason: string | null };
    };
    const vec = readVector<KnownBallot>(FILE);
    const cts = vec.outputs.ciphertexts.map(
      ([c1, c2]) => [hex(c1, 'c1'), hex(c2, 'c2')] as [Uint8Array, Uint8Array]
    );

    // The canonical Schnorr preimage is the single most drift-prone byte string
    // in the protocol: every ballot signature depends on its exact layout, and a
    // mismatch would invalidate every ballot rather than fail loudly.
    it('reproduces the canonical ballot preimage byte-for-byte', () => {
      const preimage = canonicalBallotMessage({
        electionId: hex(vec.inputs.electionId, 'electionId'),
        pseudonym: hex(vec.inputs.pseudonym, 'pseudonym'),
        ciphertexts: cts,
        zkProof: hex(vec.outputs.zkProof, 'zkProof')
      });
      expect(Buffer.from(preimage).toString('hex')).toBe(
        hex(vec.outputs.canonical_preimage, 'canonical_preimage').reduce(
          (s, b) => s + b.toString(16).padStart(2, '0'),
          ''
        )
      );
    });

    it('verifies the pinned ballot', () => {
      const mpk = G2Point.fromBytes(hex(vec.inputs.mpk, 'mpk'));
      try {
        const r = verifyBallot(
          {
            electionId: hex(vec.inputs.electionId, 'electionId'),
            pseudonym: hex(vec.inputs.pseudonym, 'pseudonym'),
            vk: hex(vec.inputs.vk, 'vk'),
            ciphertexts: cts,
            zkProof: hex(vec.outputs.zkProof, 'zkProof'),
            voterSignature: hex(vec.outputs.voterSignature, 'voterSignature'),
            wrAttestation: new Uint8Array(0)
          },
          vec.inputs.params,
          mpk,
          () => true
        );
        expect(r.ok).toBe(vec.expected.verifyBallot);
      } finally {
        mpk.destroyWasm();
      }
    });
  });

  describe('flow/ full election (level 1)', () => {
    const FILE = 'flow/full_election_level1.json';
    handled.add(FILE);
    const vec = readVector<FlowVector>(FILE);
    const { config, finalizedKey, ballots, aggregate, result } = vec;
    const electionId = hex(config.electionId, 'config.electionId');

    const reasonBySeq = new Map(
      aggregate.exclusions.map(x => [x.sequenceNumber, x.reason])
    );

    it('every ballot verifies exactly as its exclusion reason implies', () => {
      const mpk = G2Point.fromBytes(hex(finalizedKey.pkElection, 'pkElection'));
      try {
        ballots.forEach((b, seq) => {
          const reason = reasonBySeq.get(seq);
          const expectValid = !(reason && CRYPTO_FAILURE_REASONS.has(reason));
          const r = verifyBallot(
            {
              electionId: hex(b.electionId, 'electionId'),
              pseudonym: hex(b.pseudonym, 'pseudonym'),
              vk: hex(b.vk, 'vk'),
              ciphertexts: b.ciphertexts.map(
                c =>
                  [hex(c.c1, 'c1'), hex(c.c2, 'c2')] as [Uint8Array, Uint8Array]
              ),
              zkProof: hex(b.zkProof, 'zkProof'),
              voterSignature: hex(b.voterSignature, 'voterSignature'),
              wrAttestation: new Uint8Array(0)
            },
            config,
            mpk,
            () => true
          );
          expect({ seq, ok: r.ok }).toEqual({ seq, ok: expectValid });
        });
      } finally {
        mpk.destroyWasm();
      }
    });

    it('every ballot attestation verifies against the eligibility key', () => {
      const eligibilityKey = hex(config.eligibilityKey, 'eligibilityKey');
      ballots.forEach((b, seq) => {
        const ok = verifyAttestation(
          eligibilityKey,
          {
            electionId: hex(b.attestation.electionId, 'att.electionId'),
            pseudonym: hex(b.attestation.pseudonym, 'att.pseudonym'),
            vk: hex(b.attestation.vk, 'att.vk'),
            weight: BigInt(b.attestation.weight),
            nonce: BigInt(b.attestation.nonce),
            signature: hex(b.attestation.signature, 'att.signature'),
            scheme: b.attestation.scheme
          },
          { electionId, maxWeight: BigInt(config.maxWeight) }
        );
        expect({ seq, ok }).toEqual({ seq, ok: true });
      });
    });

    // The property Phase 1's exit gate needs: an independent implementation,
    // given the same admitted set and the same attested weights, reproduces the
    // published aggregate exactly. Byte equality is the requirement — the
    // integration makes an aggregate canonical only at a t+1 *byte-identical*
    // keyper quorum, so "mathematically equal" is not good enough.
    it('recomputes the weighted aggregate byte-for-byte', () => {
      const acc: Array<Ciphertext | null> = new Array(
        config.numCandidates
      ).fill(null);
      // Accumulating over ballots on a fixed WASM heap: free each superseded
      // point immediately, or intermediates pile up until GC happens to run.
      try {
        for (const seq of aggregate.admitted) {
          const b = ballots[seq]!;
          const w = BigInt(b.attestation.weight);
          for (let j = 0; j < config.numCandidates; j++) {
            const raw: Ciphertext = {
              c1: G2Point.fromBytes(hex(b.ciphertexts[j]!.c1, 'c1')),
              c2: G2Point.fromBytes(hex(b.ciphertexts[j]!.c2, 'c2'))
            };
            const weighted = w === 1n ? raw : scalarMulCt(w, raw);
            if (w !== 1n) {
              raw.c1.destroyWasm();
              raw.c2.destroyWasm();
            }
            const prev = acc[j];
            if (prev === null) {
              acc[j] = weighted;
            } else {
              acc[j] = addCt(prev, weighted);
              prev.c1.destroyWasm();
              prev.c2.destroyWasm();
              weighted.c1.destroyWasm();
              weighted.c2.destroyWasm();
            }
          }
        }

        const got = acc.map(ct => ({
          c1: Buffer.from(ct!.c1.toBytes()).toString('hex'),
          c2: Buffer.from(ct!.c2.toBytes()).toString('hex')
        }));
        const want = aggregate.aggregates.map(ct => ({
          c1: Buffer.from(hex(ct.c1, 'c1')).toString('hex'),
          c2: Buffer.from(hex(ct.c2, 'c2')).toString('hex')
        }));
        expect(got).toEqual(want);
      } finally {
        for (const ct of acc) {
          ct?.c1.destroyWasm();
          ct?.c2.destroyWasm();
        }
      }
    });

    it('derives the BSGS bound as budget × total admitted weight', () => {
      expect(result.bsgsBound).toBe(
        config.budget * aggregate.totalAdmittedWeight
      );
    });

    it('recovers the published totals from t+1 shares', () => {
      const ctSums: Ciphertext[] = aggregate.aggregates.map(ct => ({
        c1: G2Point.fromBytes(hex(ct.c1, 'agg.c1')),
        c2: G2Point.fromBytes(hex(ct.c2, 'agg.c2'))
      }));
      const committeePKs = finalizedKey.committeePKs.map(p =>
        G2Point.fromBytes(hex(p, 'committeePK'))
      );
      // geg's share envelope is per-keyper with one entry per candidate;
      // recoverTally wants the transpose, indexed [candidate][share].
      const sharesPerCandidate = aggregate.aggregates.map((_, j) =>
        vec.shares.map(s => ({
          keyperIndex: s.keyperIndex,
          sigma: G2Point.fromBytes(hex(s.entries[j]!.sigma, 'sigma')),
          proof: decodeDLEQ(hex(s.entries[j]!.proof, 'proof'))
        }))
      );
      try {
        const totals = recoverTally({
          ctSums,
          sharesPerCandidate,
          threshold: config.threshold.t,
          committeePKs,
          upperBound: BigInt(result.bsgsBound),
          transcriptFor: (j: number) => {
            const t = new Transcript('SHUTTER-VOTE-DECRYPT-v1');
            t.append('electionId', electionId);
            t.append('candidate', u16BE(j));
            return t;
          }
        });
        expect(totals.map(String)).toEqual(result.totals.map(String));
      } finally {
        for (const ct of ctSums) {
          ct.c1.destroyWasm();
          ct.c2.destroyWasm();
        }
        for (const pk of committeePKs) pk.destroyWasm();
        for (const perCandidate of sharesPerCandidate) {
          for (const s of perCandidate) s.sigma.destroyWasm();
        }
      }
    });
  });

  // Not decoration: without this, a vector geg adds later would sit on disk
  // unchecked and the gate would still report green.
  it('checks every vector file in the geg corpus', () => {
    const all = listAllVectorFiles(GEG_VECTORS_DIR);
    expect(all.length).toBeGreaterThan(0);
    expect([...handled].sort()).toEqual(all);
  });
});
