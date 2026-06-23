import { beforeAll, describe, expect, it } from 'vitest';
import { initCurves } from '@snapshot-labs/private-vote-sdk';
import { buildTeBallotEnvelope, pseudonymFor } from './teBallot';

beforeAll(async () => {
  await initCurves();
});

describe('pseudonymFor', () => {
  it('is deterministic', () => {
    const a = pseudonymFor(
      '0x1111111111111111111111111111111111111111',
      '0x' + '22'.repeat(32)
    );
    const b = pseudonymFor(
      '0x1111111111111111111111111111111111111111',
      '0x' + '22'.repeat(32)
    );
    expect(Buffer.from(a).toString('hex')).toBe(Buffer.from(b).toString('hex'));
  });

  it('returns 32 bytes', () => {
    const out = pseudonymFor(
      '0x1111111111111111111111111111111111111111',
      '0x' + '22'.repeat(32)
    );
    expect(out).toHaveLength(32);
  });

  it('changes with voter address', () => {
    const a = pseudonymFor('0x' + '11'.repeat(20), '0x' + '22'.repeat(32));
    const b = pseudonymFor('0x' + 'aa'.repeat(20), '0x' + '22'.repeat(32));
    expect(Buffer.from(a).toString('hex')).not.toBe(Buffer.from(b).toString('hex'));
  });

  it('changes with proposal id', () => {
    const a = pseudonymFor('0x' + '11'.repeat(20), '0x' + '22'.repeat(32));
    const b = pseudonymFor('0x' + '11'.repeat(20), '0x' + '33'.repeat(32));
    expect(Buffer.from(a).toString('hex')).not.toBe(Buffer.from(b).toString('hex'));
  });
});

describe('buildTeBallotEnvelope — input validation', () => {
  const BASE_ARGS = {
    voter: '0x' + '11'.repeat(20),
    proposalId: '0x' + '22'.repeat(32),
    mpk: '0x' + 'ab'.repeat(96),
    config: { variant: 'A' as const, mode: 'exact' as const, budget: 1, numCandidates: 3 },
    choice: 1
  };

  it('rejects Variant B', async () => {
    await expect(
      buildTeBallotEnvelope({ ...BASE_ARGS, config: { ...BASE_ARGS.config, variant: 'B' as any } })
    ).rejects.toThrow('only Variant A exact B=1');
  });

  it('rejects atMost mode', async () => {
    await expect(
      buildTeBallotEnvelope({ ...BASE_ARGS, config: { ...BASE_ARGS.config, mode: 'atMost' as any } })
    ).rejects.toThrow('only Variant A exact B=1');
  });

  it('rejects budget != 1', async () => {
    await expect(
      buildTeBallotEnvelope({ ...BASE_ARGS, config: { ...BASE_ARGS.config, budget: 5 } })
    ).rejects.toThrow('only Variant A exact B=1');
  });

  it('rejects choice 0 (below range)', async () => {
    await expect(
      buildTeBallotEnvelope({ ...BASE_ARGS, choice: 0 })
    ).rejects.toThrow('choice 0 out of');
  });

  it('rejects choice above numCandidates', async () => {
    await expect(
      buildTeBallotEnvelope({ ...BASE_ARGS, choice: 4 })
    ).rejects.toThrow('choice 4 out of');
  });

  it('rejects non-integer choice', async () => {
    await expect(
      buildTeBallotEnvelope({ ...BASE_ARGS, choice: 1.5 })
    ).rejects.toThrow('choice 1.5 out of');
  });

  it('rejects malformed mpk hex (bad on-curve bytes)', async () => {
    // All-zero bytes are not a valid compressed G2 point.
    await expect(
      buildTeBallotEnvelope({ ...BASE_ARGS, mpk: '0x' + '00'.repeat(96) })
    ).rejects.toThrow();
  });
});
