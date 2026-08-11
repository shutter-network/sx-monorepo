/**
 * The shared cross-implementation vector runner.
 *
 * Two test files drive the same assertions over two different corpora:
 *
 *   - `voting.vectors.test.ts`  → `tests/vectors/`      (this SDK's own vectors)
 *   - `geg-parity.test.ts`      → `tests/vectors-geg/`  (geg's canonical set)
 *
 * The verify logic lives here so those two can never drift apart. If a category
 * gains an assertion, both corpora get it.
 *
 * `registerVectorSuite` records every file it handled into the returned set.
 * Registration is synchronous at Jest collection time, so a caller's own `it`
 * can read that set afterwards and assert no vector was silently ignored —
 * which is the property that makes this a gate rather than a smoke test.
 */

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  buildBabyStepTable,
  Ciphertext,
  combineShares,
  encrypt,
  recoverDiscreteLogWithTable,
  schnorrVerify,
  Transcript,
  verifyBallot,
  verifyDecryptionShare
} from '../../src';
import { decodeSchnorr } from '../../src/contract/codec';
import { verifyBudget, verifyDLEQ, verifyOR } from '../../src/voting/proofs';
import {
  BallotVector,
  BudgetVector,
  decodeDLEQ,
  decodeORProof,
  DecryptShareVector,
  decToScalar,
  DLEQVector,
  EncryptVector,
  g1FromHex,
  g2FromHex,
  hexToBytes,
  ORVector,
  SchnorrVector,
  TallyVector
} from '../vectors/_schema';

/** The categories whose JSON shape this runner understands. */
export const STANDARD_CATEGORIES = [
  'encrypt',
  'dleq',
  'or',
  'budget',
  'schnorr',
  'decrypt-share',
  'ballot',
  'tally'
] as const;

export function loadCategory<T>(
  vectorsDir: string,
  category: string
): Array<{ name: string; file: string; vec: T }> {
  const dir = join(vectorsDir, category);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter(f => f.endsWith('.json'))
    .sort()
    .map(f => ({
      name: f.replace(/\.json$/, ''),
      file: `${category}/${f}`,
      vec: JSON.parse(readFileSync(join(dir, f), 'utf8')) as T
    }));
}

/** Every `<category>/<file>.json` under `vectorsDir`, relative-path form. */
export function listAllVectorFiles(vectorsDir: string): string[] {
  return readdirSync(vectorsDir, { withFileTypes: true })
    .filter(d => d.isDirectory())
    .flatMap(d =>
      readdirSync(join(vectorsDir, d.name))
        .filter(f => f.endsWith('.json'))
        .map(f => `${d.name}/${f}`)
    )
    .sort();
}

/**
 * A ballot vector comes in two shapes. The verify shape ships the finished
 * artifact (`inputs.zkProof`) for a verifier to check. The construction shape
 * ships pinned randomness plus an `outputs` block, so a second implementation
 * can rebuild the ballot and compare bytes. This runner only handles the first;
 * the caller claims the second.
 */
function isVerifyShapeBallot(vec: any): boolean {
  return typeof vec?.inputs?.zkProof === 'string';
}

export function registerVectorSuite(vectorsDir: string): Set<string> {
  const handled = new Set<string>();

  describe('encrypt/', () => {
    for (const { name, file, vec } of loadCategory<EncryptVector>(
      vectorsDir,
      'encrypt'
    )) {
      handled.add(file);
      it(name, () => {
        const mpk = g2FromHex(vec.inputs.mpk);
        const m = decToScalar(vec.inputs.m);
        const r = decToScalar(vec.inputs.r);
        const { ct } = encrypt(m, mpk, r);
        expect(ct.c1.toBytes()).toEqual(g2FromHex(vec.expected.c1).toBytes());
        expect(ct.c2.toBytes()).toEqual(g2FromHex(vec.expected.c2).toBytes());
      });
    }
  });

  describe('dleq/', () => {
    for (const { name, file, vec } of loadCategory<DLEQVector>(
      vectorsDir,
      'dleq'
    )) {
      handled.add(file);
      it(name, () => {
        const stmt = {
          base1: g2FromHex(vec.inputs.base1),
          base2: g2FromHex(vec.inputs.base2),
          point1: g2FromHex(vec.inputs.point1),
          point2: g2FromHex(vec.inputs.point2)
        };
        const proof = decodeDLEQ(hexToBytes(vec.inputs.proof));
        const ok = verifyDLEQ(
          stmt,
          proof,
          new Transcript(vec.inputs.transcript_label)
        );
        expect(ok).toBe(vec.expected.verify);
      });
    }
  });

  describe('or/', () => {
    for (const { name, file, vec } of loadCategory<ORVector>(
      vectorsDir,
      'or'
    )) {
      handled.add(file);
      it(name, () => {
        const mpk = g2FromHex(vec.inputs.mpk);
        const ct: Ciphertext = {
          c1: g2FromHex(vec.inputs.ct.c1),
          c2: g2FromHex(vec.inputs.ct.c2)
        };
        const candidates = vec.inputs.candidates.map(decToScalar);
        const proof = decodeORProof(hexToBytes(vec.inputs.or_proof_encoded));
        const ok = verifyOR(
          { ct, mpk, candidates },
          proof,
          new Transcript(vec.inputs.transcript_label)
        );
        expect(ok).toBe(vec.expected.verify);
      });
    }
  });

  describe('budget/', () => {
    for (const { name, file, vec } of loadCategory<BudgetVector>(
      vectorsDir,
      'budget'
    )) {
      handled.add(file);
      it(name, () => {
        const mpk = g2FromHex(vec.inputs.mpk);
        const ctSum: Ciphertext = {
          c1: g2FromHex(vec.inputs.ct_sum.c1),
          c2: g2FromHex(vec.inputs.ct_sum.c2)
        };
        const proof =
          vec.inputs.mode === 'exact'
            ? {
                mode: 'exact' as const,
                proof: decodeDLEQ(hexToBytes(vec.inputs.proof_encoded))
              }
            : {
                mode: 'atMost' as const,
                proof: decodeORProof(hexToBytes(vec.inputs.proof_encoded))
              };
        const ok = verifyBudget(
          { mpk, ctSum, budget: BigInt(vec.inputs.budget) },
          proof,
          new Transcript(vec.inputs.transcript_label)
        );
        expect(ok).toBe(vec.expected.verify);
      });
    }
  });

  describe('schnorr/', () => {
    for (const { name, file, vec } of loadCategory<SchnorrVector>(
      vectorsDir,
      'schnorr'
    )) {
      handled.add(file);
      it(name, () => {
        const vk = g1FromHex(vec.inputs.vk);
        const msg = hexToBytes(vec.inputs.message);
        const sig = decodeSchnorr(
          hexToBytes(vec.inputs.sig ?? vec.inputs.sig_encoded)
        );
        expect(schnorrVerify(vk, msg, sig)).toBe(vec.expected.verify);
      });
    }
  });

  describe('decrypt-share/', () => {
    for (const { name, file, vec } of loadCategory<DecryptShareVector>(
      vectorsDir,
      'decrypt-share'
    )) {
      handled.add(file);
      it(name, () => {
        const ctSum: Ciphertext = {
          c1: g2FromHex(vec.inputs.ct_sum.c1),
          c2: g2FromHex(vec.inputs.ct_sum.c2)
        };
        const committeePK = g2FromHex(vec.inputs.committee_pk);
        const share = {
          keyperIndex: vec.inputs.share.keyper_index,
          sigma: g2FromHex(vec.inputs.share.sigma),
          proof: decodeDLEQ(hexToBytes(vec.inputs.share.dleq_proof))
        };
        const ok = verifyDecryptionShare(
          ctSum,
          share,
          committeePK,
          new Transcript(vec.inputs.transcript_label)
        );
        expect(ok).toBe(vec.expected.verify);
      });
    }
  });

  describe('ballot/', () => {
    const accept = () => true;
    for (const { name, file, vec } of loadCategory<BallotVector>(
      vectorsDir,
      'ballot'
    )) {
      if (!isVerifyShapeBallot(vec)) continue; // claimed by the caller
      handled.add(file);
      it(name, () => {
        const mpk = g2FromHex(vec.inputs.mpk);
        const inputs = {
          electionId: hexToBytes(vec.inputs.election_id),
          pseudonym: hexToBytes(vec.inputs.pseudonym),
          vk: hexToBytes(vec.inputs.vk),
          ciphertexts: vec.inputs.ciphertexts.map(
            ({ c1, c2 }) =>
              [hexToBytes(c1), hexToBytes(c2)] as [Uint8Array, Uint8Array]
          ),
          zkProof: hexToBytes(vec.inputs.zkProof),
          voterSignature: hexToBytes(vec.inputs.signature),
          wrAttestation: hexToBytes(vec.inputs.wr_attestation)
        };
        const r = verifyBallot(inputs, vec.inputs.params, mpk, accept);
        expect(r.ok).toBe(vec.expected.verify);
      });
    }
  });

  describe('tally/', () => {
    for (const { name, file, vec } of loadCategory<TallyVector>(
      vectorsDir,
      'tally'
    )) {
      handled.add(file);
      it(name, () => {
        const ctSum: Ciphertext = {
          c1: g2FromHex(vec.inputs.ct_sum.c1),
          c2: g2FromHex(vec.inputs.ct_sum.c2)
        };
        const committeePKs = vec.inputs.committee_pks.map(g2FromHex);
        const alphas = vec.inputs.alphas.map(decToScalar);
        const upperBound = decToScalar(vec.inputs.upper_bound);
        const shares = vec.inputs.shares.map(s => ({
          keyperIndex: s.keyper_index,
          sigma: g2FromHex(s.sigma),
          proof: decodeDLEQ(hexToBytes(s.dleq_proof))
        }));
        // Re-verify each share's DLEQ against the committee pk at its index.
        for (const s of shares) {
          const pk = committeePKs[s.keyperIndex - 1]!;
          const ok = verifyDecryptionShare(
            ctSum,
            s,
            pk,
            new Transcript(`vec:tally:share:${s.keyperIndex}`)
          );
          expect(ok).toBe(true);
        }
        const tau = combineShares(shares, alphas, ctSum);
        const table = buildBabyStepTable(upperBound);
        const V = recoverDiscreteLogWithTable(tau, table);
        expect(V.toString()).toBe(vec.expected.V);
      });
    }
  });

  return handled;
}
