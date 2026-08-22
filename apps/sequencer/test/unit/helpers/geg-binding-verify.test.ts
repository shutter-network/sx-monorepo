/**
 * Sign as the browser does, verify as ingest does.
 *
 * The parity vectors prove the *message* matches geg's Python. This proves the
 * two halves we own actually meet: a signature produced the way the UI produces
 * one is accepted by `verifyBallotBinding`, and the substitution it exists to
 * stop is refused.
 */

import { keccak256 } from '@ethersproject/keccak256';
import {
  buildBallot,
  canonicalBallotMessage,
  encodeSchnorr,
  G2Point,
  initCurves,
  schnorrKeygen,
  schnorrSign
} from '@shutter-network/urban-verified-crypto';
import {
  eligibilityPublicKey,
  mintAttestation,
  resetIssuer
} from '../../../src/helpers/gegAttestation';
import {
  bindingMessage,
  verifyBallotBinding
} from '../../../src/helpers/gegBinding';

const ID = `0x${'f2'.repeat(32)}`;
const BUDGET = 3;
const NUM_CANDIDATES = 3;
const toHex = (b: Uint8Array) => `0x${Buffer.from(b).toString('hex')}`;

/** One ballot plus a credential for it, built exactly as the browser would. */
async function castBallot(opts: {
  pseudonym: string;
  nonce: number;
  weight?: number;
}) {
  const { sk, vk } = schnorrKeygen();
  const vkHex = toHex(vk.toBytes());
  const mpkKey = schnorrKeygen();
  const mpk = G2Point.generator();

  const built = buildBallot({
    mpk,
    electionId: Buffer.from(ID.slice(2), 'hex'),
    pseudonym: Buffer.from(opts.pseudonym.slice(2), 'hex'),
    sk,
    vk,
    votes: [BigInt(BUDGET), 0n, 0n],
    params: {
      numCandidates: NUM_CANDIDATES,
      budget: BUDGET,
      mode: 'exact',
      variant: 'A'
    },
    wrAttestation: new Uint8Array(0)
  });

  const weight = BigInt(opts.weight ?? 1);
  const attestation = {
    scheme: 'ATTESTATION_V1',
    electionId: ID,
    pseudonym: opts.pseudonym,
    vk: vkHex,
    weight: Number(weight),
    nonce: opts.nonce,
    signature: await mintAttestation({
      electionId: ID,
      pseudonym: opts.pseudonym,
      vk: vkHex,
      weight,
      nonce: BigInt(opts.nonce)
    })
  };

  const envelope = {
    electionId: ID,
    pseudonym: toHex(built.pseudonym),
    vk: vkHex,
    ciphertexts: built.ciphertexts.map(([c1, c2]: any) => ({
      c1: toHex(c1),
      c2: toHex(c2)
    })),
    zkProof: toHex(built.zkProof),
    voterSignature: toHex(built.voterSignature)
  };

  const ballotDigest = keccak256(
    canonicalBallotMessage({
      electionId: Buffer.from(ID.slice(2), 'hex'),
      pseudonym: built.pseudonym,
      ciphertexts: built.ciphertexts,
      zkProof: built.zkProof
    })
  );
  const signature = toHex(
    encodeSchnorr(
      schnorrSign(
        sk,
        vk,
        bindingMessage({
          electionId: ID,
          pseudonym: envelope.pseudonym,
          vk: vkHex,
          ballotDigest,
          attestation
        })
      )
    )
  );

  void mpkKey;
  return { envelope, attestation, signature };
}

const PSEUDO = `0x${'a1'.repeat(32)}`;

beforeAll(async () => {
  process.env.TE_ELIGIBILITY_PRIVATE_KEY = `0x${'11'.repeat(32)}`;
  resetIssuer();
  await initCurves();
  await eligibilityPublicKey();
}, 60_000);

describe('verifyBallotBinding', () => {
  it('accepts a binding signed the way the browser signs it', async () => {
    const b = await castBallot({ pseudonym: PSEUDO, nonce: 1 });
    expect(await verifyBallotBinding(b)).toBe(true);
  }, 60_000);

  // The substitution the binding exists to stop, at the sx layer: a credential
  // lifted from the voter's own later ballot onto their earlier one.
  it("refuses a credential moved from the voter's other ballot", async () => {
    const first = await castBallot({ pseudonym: PSEUDO, nonce: 1 });
    const second = await castBallot({ pseudonym: PSEUDO, nonce: 2 });
    expect(
      await verifyBallotBinding({
        envelope: first.envelope,
        attestation: second.attestation,
        signature: first.signature
      })
    ).toBe(false);
  }, 60_000);

  it('refuses a weight the voter did not sign', async () => {
    const b = await castBallot({ pseudonym: PSEUDO, nonce: 1, weight: 5 });
    expect(
      await verifyBallotBinding({
        ...b,
        attestation: { ...b.attestation, weight: 50 }
      })
    ).toBe(false);
  }, 60_000);

  it('refuses a nonce the voter did not sign', async () => {
    const b = await castBallot({ pseudonym: PSEUDO, nonce: 1 });
    expect(
      await verifyBallotBinding({
        ...b,
        attestation: { ...b.attestation, nonce: 99 }
      })
    ).toBe(false);
  }, 60_000);

  it('refuses a tampered ballot', async () => {
    const b = await castBallot({ pseudonym: PSEUDO, nonce: 1 });
    const ciphertexts = [...b.envelope.ciphertexts];
    ciphertexts[0] = { ...ciphertexts[0], c1: `0x${'99'.repeat(96)}` };
    expect(
      await verifyBallotBinding({
        ...b,
        envelope: { ...b.envelope, ciphertexts }
      })
    ).toBe(false);
  }, 60_000);

  it.each([
    ['empty', '0x'],
    ['short', `0x${'00'.repeat(79)}`],
    ['garbage', 'nope'],
    ['zeros', `0x${'00'.repeat(80)}`]
  ])(
    'returns false rather than throwing on a %s signature',
    async (_l, sig) => {
      const b = await castBallot({ pseudonym: PSEUDO, nonce: 1 });
      expect(await verifyBallotBinding({ ...b, signature: sig })).toBe(false);
    },
    60_000
  );
});
