/**
 * Cross-language parity for the ballot↔credential binding message.
 *
 * Four implementations now write this message: geg's Python, geg's browser
 * `@geg/shared`, sx's browser (`apps/ui`) and the sequencer verifying at ingest.
 * Only the Python is normative — a keyper is what ultimately admits or excludes
 * the ballot — so these vectors come from `geg/crypto/binding.py`, and this
 * asserts agreement with the protocol rather than agreement with ourselves.
 *
 * A one-byte drift is not a subtle failure but it is a well-disguised one: every
 * ballot is excluded as INVALID_ATTESTATION, the election tallies to zeros, and
 * the error reads as an eligibility problem pointing nowhere near the encoding
 * that caused it.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { GegAttestationError } from '../../../src/helpers/gegAttestation';
import {
  bindingMessage,
  credentialDigest
} from '../../../src/helpers/gegBinding';

type Case = {
  name: string;
  attestation: {
    scheme: string;
    electionId: string;
    pseudonym: string;
    vk: string;
    weight: number;
    nonce: number;
    signature: string;
  };
  ballotDigest: string;
  attestationDigest: string;
  bindingMessage: string;
  voterAttestationSignature: string;
};

const fixture = JSON.parse(
  readFileSync(
    join(
      __dirname,
      '../../../../../packages/geg-parity/vectors/binding/binding_message.json'
    ),
    'utf8'
  )
) as {
  inputs: { electionId: string; pseudonym: string; vk: string };
  cases: Case[];
};

const hex = (b: Uint8Array) => `0x${Buffer.from(b).toString('hex')}`;

const build = (c: Case) =>
  bindingMessage({
    electionId: fixture.inputs.electionId,
    pseudonym: fixture.inputs.pseudonym,
    vk: fixture.inputs.vk,
    ballotDigest: c.ballotDigest,
    attestation: c.attestation
  });

describe('bindingMessage — parity with geg', () => {
  it('has vectors covering both credential schemes', () => {
    // A V1-only corpus would prove nothing about the legacy branch, which hashes
    // an entirely different (undomained) preimage.
    const schemes = new Set(fixture.cases.map(c => c.attestation.scheme));
    expect(schemes.has('ATTESTATION_V1')).toBe(true);
    expect(schemes.has('ATTESTATION_LEGACY')).toBe(true);
  });

  it.each(fixture.cases.map(c => [c.name, c] as [string, Case]))(
    'reproduces the credential digest for %s',
    (_name, c) => {
      expect(hex(credentialDigest(c.attestation))).toBe(c.attestationDigest);
    }
  );

  it.each(fixture.cases.map(c => [c.name, c] as [string, Case]))(
    'reproduces the binding message for %s',
    (_name, c) => {
      expect(hex(build(c))).toBe(c.bindingMessage);
    }
  );

  // sx issues a unix timestamp as the nonce, and a truncating scalar encoding
  // would pass every small case above. A timestamp alone does not catch it —
  // 1.7e9 still fits in 32 bits — so the corpus carries a value past 2^32 too.
  it.each([
    ['timestamp-sized', 1_000_000_000],
    ['beyond 32 bits', 2 ** 32]
  ])('handles a %s nonce', (_label, floor) => {
    const big = fixture.cases.find(c => c.attestation.nonce > floor);
    expect(big).toBeDefined();
    expect(hex(build(big as Case))).toBe((big as Case).bindingMessage);
  });
});

describe('bindingMessage — what the voter commits to', () => {
  const base = () => fixture.cases[0];
  const withCredential = (over: Record<string, unknown>) =>
    hex(
      build({
        ...base(),
        attestation: { ...base().attestation, ...over }
      } as Case)
    );

  // The two fields no other voter-signed message covers, and the whole reason
  // this exists.
  it('changes when the weight changes', () => {
    expect(withCredential({ weight: base().attestation.weight + 1 })).not.toBe(
      base().bindingMessage
    );
  });

  it('changes when the nonce changes — the re-vote arbiter', () => {
    expect(withCredential({ nonce: base().attestation.nonce + 1 })).not.toBe(
      base().bindingMessage
    );
  });

  it("changes when the issuer's signature changes", () => {
    expect(withCredential({ signature: `0x${'99'.repeat(80)}` })).not.toBe(
      base().bindingMessage
    );
  });

  // Without this the binding would follow a credential onto any ballot.
  it('changes when the ballot changes', () => {
    expect(
      hex(build({ ...base(), ballotDigest: `0x${'99'.repeat(32)}` }))
    ).not.toBe(base().bindingMessage);
  });

  it('separates the two credential schemes', () => {
    expect(withCredential({ scheme: 'ATTESTATION_LEGACY' })).not.toBe(
      withCredential({ scheme: 'ATTESTATION_V1' })
    );
  });
});

describe('bindingMessage — rejections', () => {
  const base = () => fixture.cases[0];

  it('refuses an unknown scheme rather than signing something unverifiable', () => {
    expect(() =>
      build({
        ...base(),
        attestation: { ...base().attestation, scheme: 'ATTESTATION_V99' }
      } as Case)
    ).toThrow(GegAttestationError);
  });

  it('refuses an empty issuer signature', () => {
    expect(() =>
      build({
        ...base(),
        attestation: { ...base().attestation, signature: '0x' }
      } as Case)
    ).toThrow(/must not be empty/);
  });

  it.each([
    ['electionId', `0x${'11'.repeat(31)}`],
    ['pseudonym', `0x${'22'.repeat(33)}`],
    ['vk', `0x${'33'.repeat(47)}`],
    ['ballotDigest', `0x${'44'.repeat(31)}`]
  ])('refuses a wrong-length %s', (field, value) => {
    const args: any = {
      electionId: fixture.inputs.electionId,
      pseudonym: fixture.inputs.pseudonym,
      vk: fixture.inputs.vk,
      ballotDigest: base().ballotDigest,
      attestation: base().attestation
    };
    args[field] = value;
    expect(() => bindingMessage(args)).toThrow(
      new RegExp(`${field}: expected`)
    );
  });

  it('refuses non-hex rather than digesting it', () => {
    expect(() =>
      bindingMessage({
        electionId: fixture.inputs.electionId,
        pseudonym: fixture.inputs.pseudonym,
        vk: fixture.inputs.vk,
        ballotDigest: `0x${'zz'.repeat(32)}`,
        attestation: base().attestation
      })
    ).toThrow(GegAttestationError);
  });
});
