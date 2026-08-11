/**
 * `ATTESTATION_V1` minting — the direction hub will run in production.
 *
 * `tests/geg-parity.test.ts` proves the *verify* direction against geg's
 * canonical vectors. This file covers the *mint* direction: the credentials hub
 * issues must be ones geg's Python `verify_attestation` accepts.
 *
 * The TS-internal round trip is asserted here in CI. The cross-language half
 * needs geg's Python and therefore cannot run in sx CI (no Python toolchain by
 * design). Instead this file can emit a fixture that geg verifies out-of-band —
 * the verifier is a monorepo dev script, deliberately outside this vendored
 * package:
 *
 *   WRITE_ATTESTATION_FIXTURE=1 npx jest tests/voting.attestation.test.ts
 *   python3 ../../scripts/geg/verify-attestation-fixture.py   # needs the geg venv
 *
 * The fixture is checked in, so the last recorded cross-language result is
 * always inspectable.
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  Attestation,
  attestationMessage,
  initCurves,
  legacyAttestationMessage,
  signAttestation,
  verifyAttestation,
  verifyAttestationSig
} from '../src';
import { schnorrKeygen } from '../src/voting/schnorr';

beforeAll(async () => {
  await initCurves();
});

// Pinned so the emitted fixture is stable across runs — a fixture that churns
// on every invocation produces noisy diffs and tells you nothing.
const ELIGIBILITY_SK =
  0x2f1a4c8e9b3d7f0a5e6c1d8b4a9f3e2c7d0b6a5948372615f4e3d2c1b0a99887n;
const NONCE_K =
  0x0b7e15162398d3f4a1c9e2705f8b6d4c3a291807f6e5d4c3b2a1908f7e6d5c4bn;

function bytes(fill: number, len: number): Uint8Array {
  return new Uint8Array(len).fill(fill);
}

/** A voter vk must be a real G1 point, not arbitrary bytes. */
function someVk(seed: bigint): Uint8Array {
  const { vk } = schnorrKeygen(seed);
  try {
    return vk.toBytes();
  } finally {
    vk.destroyWasm();
  }
}

describe('ATTESTATION_V1 minting', () => {
  const eligibility = () => schnorrKeygen(ELIGIBILITY_SK);

  const base = () => ({
    electionId: bytes(0x11, 32),
    pseudonym: bytes(0x22, 32),
    vk: someVk(0x1234n),
    weight: 5n,
    nonce: 1n
  });

  it('a minted credential verifies under the issuer key', () => {
    const { sk, vk: eligVk } = eligibility();
    try {
      const fields = base();
      const signature = signAttestation(sk, eligVk, fields, NONCE_K);
      expect(signature.length).toBe(80);
      const ok = verifyAttestation(
        eligVk.toBytes(),
        { ...fields, signature },
        { electionId: fields.electionId, maxWeight: 10n }
      );
      expect(ok).toBe(true);
    } finally {
      eligVk.destroyWasm();
    }
  });

  it('is deterministic given a pinned nonce', () => {
    const { sk, vk: eligVk } = eligibility();
    try {
      const a = signAttestation(sk, eligVk, base(), NONCE_K);
      const b = signAttestation(sk, eligVk, base(), NONCE_K);
      expect(Buffer.from(a).toString('hex')).toBe(
        Buffer.from(b).toString('hex')
      );
    } finally {
      eligVk.destroyWasm();
    }
  });

  // Each of these is a way the Snapshot integration could silently mis-issue.
  it.each([
    ['weight', (a: Attestation) => ({ ...a, weight: a.weight + 1n })],
    ['nonce', (a: Attestation) => ({ ...a, nonce: a.nonce + 1n })],
    ['electionId', (a: Attestation) => ({ ...a, electionId: bytes(0x33, 32) })],
    ['pseudonym', (a: Attestation) => ({ ...a, pseudonym: bytes(0x44, 32) })],
    ['vk', (a: Attestation) => ({ ...a, vk: someVk(0x5678n) })]
  ])('rejects a credential with a tampered %s', (_label, tamper) => {
    const { sk, vk: eligVk } = eligibility();
    try {
      const fields = base();
      const signature = signAttestation(sk, eligVk, fields, NONCE_K);
      const tampered = tamper({ ...fields, signature });
      expect(verifyAttestationSig(eligVk.toBytes(), tampered)).toBe(false);
    } finally {
      eligVk.destroyWasm();
    }
  });

  it('rejects a weight above maxWeight before touching the signature', () => {
    const { sk, vk: eligVk } = eligibility();
    try {
      const fields = { ...base(), weight: 50n };
      const signature = signAttestation(sk, eligVk, fields, NONCE_K);
      // The signature itself is valid — only the ceiling rejects it.
      expect(
        verifyAttestationSig(eligVk.toBytes(), { ...fields, signature })
      ).toBe(true);
      expect(
        verifyAttestation(
          eligVk.toBytes(),
          { ...fields, signature },
          { electionId: fields.electionId, maxWeight: 10n }
        )
      ).toBe(false);
    } finally {
      eligVk.destroyWasm();
    }
  });

  it('rejects a credential bound to a different election than expected', () => {
    const { sk, vk: eligVk } = eligibility();
    try {
      const fields = base();
      const signature = signAttestation(sk, eligVk, fields, NONCE_K);
      expect(
        verifyAttestation(
          eligVk.toBytes(),
          { ...fields, signature },
          { electionId: bytes(0x99, 32), maxWeight: 10n }
        )
      ).toBe(false);
    } finally {
      eligVk.destroyWasm();
    }
  });

  it('refuses to mint out-of-range weight or nonce', () => {
    const { sk, vk: eligVk } = eligibility();
    try {
      expect(() =>
        signAttestation(sk, eligVk, { ...base(), weight: 0n }, NONCE_K)
      ).toThrow(/weight must be >= 1/);
      expect(() =>
        signAttestation(sk, eligVk, { ...base(), nonce: 0n }, NONCE_K)
      ).toThrow(/nonce must be >= 1/);
    } finally {
      eligVk.destroyWasm();
    }
  });

  it('rejects malformed field sizes', () => {
    expect(() =>
      attestationMessage(bytes(1, 31), bytes(2, 32), someVk(1n), 1n, 1n)
    ).toThrow(/electionId must be 32 bytes/);
    expect(() =>
      attestationMessage(bytes(1, 32), bytes(2, 33), someVk(1n), 1n, 1n)
    ).toThrow(/pseudonym must be 32 bytes/);
    expect(() =>
      attestationMessage(bytes(1, 32), bytes(2, 32), bytes(3, 47), 1n, 1n)
    ).toThrow(/vk must be 48 bytes/);
  });

  it('the legacy digest is a bare concatenation, distinct from V1', () => {
    const eid = bytes(0x11, 32);
    const pseudo = bytes(0x22, 32);
    const vk = someVk(0x1234n);
    const legacy = legacyAttestationMessage(eid, pseudo, vk);
    const v1 = attestationMessage(eid, pseudo, vk, 1n, 1n);
    expect(Buffer.from(legacy).toString('hex')).not.toBe(
      Buffer.from(v1).toString('hex')
    );
  });

  it('emits the cross-language fixture when asked', () => {
    const cases = [
      { name: 'v1_weight1_nonce1', weight: 1n, nonce: 1n, maxWeight: 10n },
      { name: 'v1_weight5_nonce1', weight: 5n, nonce: 1n, maxWeight: 10n },
      { name: 'v1_weight7_nonce42', weight: 7n, nonce: 42n, maxWeight: 10n },
      {
        // A realistic Snapshot weight: round(vp) with maxWeight = 2^53-1 (D11).
        name: 'v1_large_weight_max_weight',
        weight: 123456789n,
        nonce: 1770000000n,
        maxWeight: 9007199254740991n
      }
    ];
    const { sk, vk: eligVk } = eligibility();
    let fixture: any;
    try {
      fixture = {
        description:
          'ATTESTATION_V1 credentials minted by the TypeScript implementation. ' +
          "geg's Python verify_attestation must accept every one.",
        eligibilityKey: `0x${Buffer.from(eligVk.toBytes()).toString('hex')}`,
        cases: cases.map(c => {
          const fields = { ...base(), weight: c.weight, nonce: c.nonce };
          const signature = signAttestation(sk, eligVk, fields, NONCE_K);
          // Never emit a fixture we would not accept ourselves.
          expect(
            verifyAttestation(
              eligVk.toBytes(),
              { ...fields, signature },
              { electionId: fields.electionId, maxWeight: c.maxWeight }
            )
          ).toBe(true);
          return {
            name: c.name,
            scheme: 'ATTESTATION_V1',
            electionId: `0x${Buffer.from(fields.electionId).toString('hex')}`,
            pseudonym: `0x${Buffer.from(fields.pseudonym).toString('hex')}`,
            vk: `0x${Buffer.from(fields.vk).toString('hex')}`,
            weight: c.weight.toString(),
            nonce: c.nonce.toString(),
            maxWeight: c.maxWeight.toString(),
            signature: `0x${Buffer.from(signature).toString('hex')}`,
            expected: { verify: true }
          };
        })
      };
    } finally {
      eligVk.destroyWasm();
    }

    if (process.env.WRITE_ATTESTATION_FIXTURE) {
      writeFileSync(
        join(__dirname, 'fixtures', 'ts-minted-attestations.json'),
        `${JSON.stringify(fixture, null, 2)}\n`
      );
    }
    expect(fixture.cases).toHaveLength(cases.length);
  });
});
