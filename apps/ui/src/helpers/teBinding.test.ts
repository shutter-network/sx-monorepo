import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  BallotCredential,
  bindingMessage,
  credentialDigest
} from './teBinding';

type Case = {
  name: string;
  attestation: BallotCredential;
  ballotDigest: string;
  attestationDigest: string;
  bindingMessage: string;
};

const fixture = JSON.parse(
  readFileSync(
    join(
      __dirname,
      '../../../../packages/geg-parity/vectors/binding/binding_message.json'
    ),
    'utf8'
  )
) as {
  inputs: { electionId: string; pseudonym: string; vk: string };
  cases: Case[];
};

const hex = (b: Uint8Array) =>
  `0x${Array.from(b, x => x.toString(16).padStart(2, '0')).join('')}`;

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
    const schemes = new Set(fixture.cases.map(c => c.attestation.scheme));
    expect(schemes.has('ATTESTATION_V1')).toBe(true);
    expect(schemes.has('ATTESTATION_LEGACY')).toBe(true);
  });

  it.each(fixture.cases.map(c => [c.name, c] as const))(
    'reproduces the credential digest for %s',
    (_n, c) =>
      expect(hex(credentialDigest(c.attestation))).toBe(c.attestationDigest)
  );

  it.each(fixture.cases.map(c => [c.name, c] as const))(
    'reproduces the binding message for %s',
    (_n, c) => expect(hex(build(c))).toBe(c.bindingMessage)
  );

  // A unix timestamp still fits in 32 bits, so it does not catch a truncating
  // scalar encoding on its own — the corpus carries a larger value too.
  it.each([
    ['timestamp-sized', 1_000_000_000],
    ['beyond 32 bits', 2 ** 32]
  ])('handles a %s nonce', (_l, floor) => {
    const big = fixture.cases.find(c => c.attestation.nonce > floor);
    expect(big).toBeDefined();
    expect(hex(build(big as Case))).toBe((big as Case).bindingMessage);
  });
});

describe('bindingMessage — what the voter commits to', () => {
  const base = () => fixture.cases[0];
  const withCred = (over: Partial<BallotCredential>) =>
    hex(build({ ...base(), attestation: { ...base().attestation, ...over } }));

  // The two fields nothing else voter-signed covers, and the whole point.
  it('changes when the weight changes', () =>
    expect(withCred({ weight: base().attestation.weight + 1 })).not.toBe(
      base().bindingMessage
    ));

  it('changes when the nonce changes — the re-vote arbiter', () =>
    expect(withCred({ nonce: base().attestation.nonce + 1 })).not.toBe(
      base().bindingMessage
    ));

  it("changes when the issuer's signature changes", () =>
    expect(withCred({ signature: `0x${'99'.repeat(80)}` })).not.toBe(
      base().bindingMessage
    ));

  // Without this the binding would follow a credential onto any ballot.
  it('changes when the ballot changes', () =>
    expect(
      hex(build({ ...base(), ballotDigest: `0x${'99'.repeat(32)}` }))
    ).not.toBe(base().bindingMessage));
});
