import { expectedPseudonym, verifyTeBallot } from '../../../src/helpers/te';

describe('helpers/te', () => {
  describe('expectedPseudonym', () => {
    test('is deterministic for fixed inputs', () => {
      const a = expectedPseudonym(
        '0x1111111111111111111111111111111111111111',
        '0x2222222222222222222222222222222222222222222222222222222222222222'
      );
      const b = expectedPseudonym(
        '0x1111111111111111111111111111111111111111',
        '0x2222222222222222222222222222222222222222222222222222222222222222'
      );
      expect(a).toBe(b);
      expect(a).toMatch(/^0x[0-9a-f]{64}$/);
    });

    test('changes with the proposal id', () => {
      const a = expectedPseudonym(
        '0x1111111111111111111111111111111111111111',
        '0x2222222222222222222222222222222222222222222222222222222222222222'
      );
      const b = expectedPseudonym(
        '0x1111111111111111111111111111111111111111',
        '0x3333333333333333333333333333333333333333333333333333333333333333'
      );
      expect(a).not.toBe(b);
    });
  });

  describe('verifyTeBallot — structural rejections', () => {
    const proposal = {
      id: '0x2222222222222222222222222222222222222222222222222222222222222222',
      te_config: {
        numCandidates: 2,
        budget: 1,
        mode: 'exact' as const,
        variant: 'A' as const
      },
      te_mpk: '0x' + 'ab'.repeat(96)
    };

    test('rejects when te_config missing', async () => {
      const r = await verifyTeBallot(
        { ...proposal, te_config: null },
        '0x1111111111111111111111111111111111111111',
        '{}'
      );
      expect(r).toEqual({ ok: false, reason: 'proposal_missing_te_config' });
    });

    test('rejects when DKG not finalised', async () => {
      const r = await verifyTeBallot(
        { ...proposal, te_mpk: null },
        '0x1111111111111111111111111111111111111111',
        '{}'
      );
      expect(r).toEqual({ ok: false, reason: 'proposal_dkg_not_finalized' });
    });

    test('rejects malformed JSON envelope', async () => {
      const r = await verifyTeBallot(
        proposal,
        '0x1111111111111111111111111111111111111111',
        'not json'
      );
      expect(r).toEqual({ ok: false, reason: 'choice_not_json_envelope' });
    });

    test('rejects pseudonym mismatch', async () => {
      const envelope = {
        electionId: '0x' + '11'.repeat(32),
        // Wrong pseudonym — does not equal keccak256(voter || proposalId).
        pseudonym: '0x' + '00'.repeat(32),
        vk: '0x' + '00'.repeat(48),
        ciphertexts: [],
        zkProof: '0x',
        voterSignature: '0x' + '00'.repeat(80),
        wrAttestation: '0x'
      };
      const r = await verifyTeBallot(
        proposal,
        '0x1111111111111111111111111111111111111111',
        JSON.stringify(envelope)
      );
      expect(r).toEqual({ ok: false, reason: 'pseudonym_mismatch' });
    });
  });
});
