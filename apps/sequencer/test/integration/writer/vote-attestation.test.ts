/**
 * The eligibility credential is written with the vote, on the same row.
 *
 * These assertions are the reason the credential is three columns on `votes`
 * rather than a side table. A separate table keyed on the vote id would have
 * needed an explicit delete-by-previous-id on re-vote, and a second write that
 * could fail independently of the first — leaving a vote whose credential is
 * missing, which the hub's ballot feed refuses to serve, which stalls the whole
 * tally. Columns make both impossible, and these tests are what hold that.
 */

import {
  G1Point,
  initCurves,
  schnorrVerify
} from '@shutter-network/urban-verified-crypto';
import snapshot from '@snapshot-labs/snapshot.js';
import * as actions from '../../../src/helpers/actions';
import {
  attestationMessage,
  eligibilityPublicKey,
  mintAttestation,
  resetIssuer
} from '../../../src/helpers/gegAttestation';
import db, { sequencerDB } from '../../../src/helpers/mysql';
import * as teHelper from '../../../src/helpers/te';
import * as scores from '../../../src/scores';
import { action, verify } from '../../../src/writer/vote';

const SPACE = 'test.eth';
// Deliberately not the address other suites use as a proposal author. `action()`
// upserts a `leaderboard` row for the voter, and `delete-proposal` decrements
// `proposal_count` on that same row — from zero, if this suite created it, which
// underflows an unsigned column and fails a test in a different file.
const VOTER = '0x000000000000000000000000000000000A77E571';
const ISSUER_SK =
  '0x0000000000000000000000000000000000000000000000000000000000002a2a';

// action() finalises by recomputing scores, which for a public proposal reaches
// the score API. Stubbed so these tests exercise the write and nothing else.
jest.spyOn(scores, 'updateProposalAndVotes').mockResolvedValue(true);

function bytes(hex: string): Uint8Array {
  return new Uint8Array(
    Buffer.from(hex.startsWith('0x') ? hex.slice(2) : hex, 'hex')
  );
}

const PSEUDONYM = `0x${'22'.repeat(32)}`;
const VK = `0x${'ab'.repeat(48)}`;

function envelope() {
  return {
    electionId: `0x${'11'.repeat(32)}`,
    pseudonym: PSEUDONYM,
    vk: VK,
    ciphertexts: [],
    zkProof: '0x',
    voterSignature: `0x${'00'.repeat(80)}`,
    wrAttestation: '0x'
  };
}

function body(proposalId: string, timestamp: number) {
  return {
    address: VOTER,
    msg: JSON.stringify({
      space: SPACE,
      timestamp: String(timestamp),
      payload: {
        proposal: proposalId,
        choice: envelope(),
        metadata: {},
        app: '',
        reason: ''
      }
    })
  };
}

function context(attestation: any) {
  return {
    proposal: { id: 'unused', strategies: [] },
    vp: { vp: 42, vp_by_strategy: [42], vp_state: 'final' },
    attestation
  };
}

async function seedProposal(id: string, privacy: string) {
  await db.queryAsync('DELETE FROM proposals WHERE id = ?', [id]);
  await db.queryAsync('INSERT INTO proposals SET ?', {
    id,
    ipfs: `bafkrei${id.slice(-12)}`,
    author: VOTER,
    created: 1,
    space: SPACE,
    network: '1',
    symbol: '',
    type: 'weighted',
    strategies: '[]',
    validation: '{}',
    plugins: '{}',
    title: 'attestation fixture',
    body: '',
    discussion: '',
    choices: JSON.stringify(['A', 'B']),
    start: 1,
    end: 2_000_000_000,
    quorum: 0,
    privacy,
    snapshot: 1,
    app: '',
    scores: '[]',
    scores_by_strategy: '[]',
    scores_state: 'pending',
    scores_total: 0,
    scores_updated: 0,
    vp_value_by_strategy: '[]',
    votes: 0
  });
}

async function voteRow(proposalId: string): Promise<any> {
  const rows = await db.queryAsync(
    'SELECT id, created, te_weight, te_nonce, te_attestation FROM votes WHERE proposal = ? AND voter = ?',
    [proposalId, VOTER]
  );
  return rows[0];
}

describe('vote: the credential is written with the vote', () => {
  let issuerKey: string;

  beforeAll(async () => {
    process.env.TE_ELIGIBILITY_PRIVATE_KEY = ISSUER_SK;
    resetIssuer();
    issuerKey = await eligibilityPublicKey();
    await initCurves();
  });

  afterAll(async () => {
    await db.queryAsync('DELETE FROM votes WHERE space = ?', [SPACE]);
    await db.queryAsync('DELETE FROM proposals WHERE space = ?', [SPACE]);
    // `action()` upserts a leaderboard row; leaving it behind changes the
    // starting state for any suite that decrements those counters.
    await db.queryAsync(
      'DELETE FROM leaderboard WHERE space = ? AND user = ?',
      [SPACE, VOTER]
    );
    await db.endAsync();
    await sequencerDB.endAsync();
  });

  beforeEach(async () => {
    await db.queryAsync('DELETE FROM votes WHERE space = ?', [SPACE]);
  });

  async function credential(proposalId: string, weight: bigint, nonce: bigint) {
    const signature = await mintAttestation({
      electionId: proposalId,
      pseudonym: PSEUDONYM,
      vk: VK,
      weight,
      nonce
    });
    return { weight: Number(weight), nonce: Number(nonce), signature };
  }

  it('stores a credential that verifies against the frozen key', async () => {
    const id = `0x${'a1'.repeat(32)}`;
    await seedProposal(id, 'shutter-elgamal');
    const nonce = 1_700_000_000;
    const att = await credential(id, 7n, BigInt(nonce));

    await action(body(id, nonce), 'ipfs1', {}, '0xvote1', context(att));

    const row = await voteRow(id);
    expect(row.te_weight).toBe(7);
    expect(row.te_nonce).toBe(nonce);
    expect(row.te_attestation).toBe(att.signature);

    // The stored bytes are a credential the committee would accept, not merely a
    // string that round-tripped through the database.
    const issuer = G1Point.fromBytes(bytes(issuerKey));
    const sig = bytes(row.te_attestation);
    const R = G1Point.fromBytes(sig.subarray(0, 48));
    let s = 0n;
    for (const b of sig.subarray(48)) s = (s << 8n) | BigInt(b);
    const message = attestationMessage(
      bytes(id),
      bytes(PSEUDONYM),
      bytes(VK),
      BigInt(row.te_weight),
      BigInt(row.te_nonce)
    );
    expect(schnorrVerify(issuer, message, { R, s })).toBe(true);
    issuer.destroyWasm();
    R.destroyWasm();
  });

  // The case a side table would have got wrong. `created` changes on a re-vote,
  // so the old credential's nonce is stale; keyed on the vote id it would be
  // orphaned rather than replaced, and the feed would serve a nonce that does
  // not match the row it sits on.
  it('replaces the credential on a re-vote, carrying the new nonce', async () => {
    const id = `0x${'a2'.repeat(32)}`;
    await seedProposal(id, 'shutter-elgamal');

    const first = 1_700_000_000;
    await action(
      body(id, first),
      'ipfs1',
      {},
      '0xvote1',
      context(await credential(id, 3n, BigInt(first)))
    );

    const second = first + 60;
    await action(
      body(id, second),
      'ipfs2',
      {},
      '0xvote2',
      context(await credential(id, 9n, BigInt(second)))
    );

    const rows = await db.queryAsync(
      'SELECT id, created, te_weight, te_nonce FROM votes WHERE proposal = ? AND voter = ?',
      [id, VOTER]
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe('0xvote2');
    expect(rows[0].created).toBe(second);
    expect(rows[0].te_nonce).toBe(second);
    expect(rows[0].te_weight).toBe(9);
  });

  // The nonce must equal `created`: the protocol ranks duplicate ballots by
  // (nonce, sequenceNumber) under last-wins, which is how Snapshot's "newer vote
  // wins" rule is expressed to the committee. A nonce that drifts from `created`
  // silently reorders re-votes at tally time.
  it('keeps the nonce equal to the vote timestamp', async () => {
    const id = `0x${'a3'.repeat(32)}`;
    await seedProposal(id, 'shutter-elgamal');
    const ts = 1_700_000_123;
    await action(
      body(id, ts),
      'ipfs1',
      {},
      '0xvote1',
      context(await credential(id, 5n, BigInt(ts)))
    );
    const row = await voteRow(id);
    expect(row.te_nonce).toBe(row.created);
  });

  it('leaves the columns NULL on a public proposal', async () => {
    const id = `0x${'a4'.repeat(32)}`;
    await seedProposal(id, '');
    await action(
      body(id, 1_700_000_000),
      'ipfs1',
      {},
      '0xvote1',
      // verify() attaches no credential for a public proposal.
      { ...context(null), attestation: null }
    );
    const row = await voteRow(id);
    expect(row.te_weight).toBeNull();
    expect(row.te_nonce).toBeNull();
    expect(row.te_attestation).toBeNull();
  });
});

/**
 * The wiring: that `verify()` mints at all, clamps to the ceiling, and does
 * neither for a public proposal.
 *
 * `verifyTeBallot` and `getVp` are stubbed. The ballot crypto and the score
 * lookup are not what is under test here — both are covered elsewhere — and
 * building a real encrypted ballot to reach the minting code would test the SDK
 * rather than this branch.
 */
describe('vote verify(): minting and the clamp', () => {
  const PROPOSAL = `0x${'b1'.repeat(32)}`;

  beforeAll(() => {
    process.env.TE_ELIGIBILITY_PRIVATE_KEY = ISSUER_SK;
    resetIssuer();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  function proposalFixture(privacy: string, budget: number) {
    return {
      id: PROPOSAL,
      space: SPACE,
      network: '1',
      type: budget === 1 ? 'basic' : 'weighted',
      strategies: [],
      snapshot: 1,
      start: 1,
      end: 2_000_000_000,
      privacy,
      choices: ['A', 'B'],
      validation: { name: 'any' },
      te_config: {
        numCandidates: 2,
        budget,
        mode: 'exact',
        variant: 'A'
      } as any,
      te_mpk: `0x${'00'.repeat(96)}`
    };
  }

  async function runVerify(privacy: string, budget: number, vp: number) {
    jest
      .spyOn(actions, 'getProposal')
      .mockResolvedValue(proposalFixture(privacy, budget) as any);
    jest
      .spyOn(teHelper, 'verifyTeBallot')
      .mockResolvedValue({ ok: true } as any);
    jest.spyOn(snapshot.utils, 'getVp').mockResolvedValue({
      vp,
      vp_by_strategy: [vp],
      vp_state: 'final'
    } as any);
    jest.spyOn(snapshot.utils, 'validateSchema').mockReturnValue(true);

    // A public proposal validates `choice` against its own type, so it cannot be
    // handed a ballot envelope — that is the shape a private proposal expects.
    const msg =
      privacy === 'shutter-elgamal'
        ? body(PROPOSAL, 1_700_000_000)
        : {
            address: VOTER,
            msg: JSON.stringify({
              space: SPACE,
              timestamp: '1700000000',
              payload: {
                proposal: PROPOSAL,
                choice: 1,
                metadata: {},
                app: '',
                reason: ''
              }
            })
          };
    return verify(msg);
  }

  it('mints a credential for a private proposal', async () => {
    const ctx: any = await runVerify('shutter-elgamal', 100, 42);
    expect(ctx.attestation).not.toBeNull();
    expect(ctx.attestation.weight).toBe(42);
    expect(ctx.attestation.nonce).toBe(1_700_000_000);
    expect(ctx.attestation.signature).toMatch(/^0x[0-9a-f]{160}$/);
  });

  // Over-cap voting power is counted AT the cap. The committee rejects an
  // attested weight above maxWeight outright, so attesting the raw figure would
  // drop the whale from the tally entirely rather than counting it at the limit.
  it('clamps a weighted proposal at 10,000', async () => {
    const ctx: any = await runVerify('shutter-elgamal', 100, 25_000);
    expect(ctx.attestation.weight).toBe(10_000);
  });

  it('clamps a basic proposal at 1,000,000', async () => {
    const ctx: any = await runVerify('shutter-elgamal', 1, 5_000_000);
    expect(ctx.attestation.weight).toBe(1_000_000);
  });

  it('rounds to a whole number', async () => {
    const ctx: any = await runVerify('shutter-elgamal', 100, 1.4);
    expect(ctx.attestation.weight).toBe(1);
  });

  it.each([
    ['an object, as getProposal returns it', false],
    ['a raw JSON string', true]
  ])('reads the budget when te_config is %s', async (_label, asString) => {
    const fixture = proposalFixture('shutter-elgamal', 100);
    if (asString) fixture.te_config = JSON.stringify(fixture.te_config) as any;
    jest.spyOn(actions, 'getProposal').mockResolvedValue(fixture as any);
    jest
      .spyOn(teHelper, 'verifyTeBallot')
      .mockResolvedValue({ ok: true } as any);
    jest.spyOn(snapshot.utils, 'getVp').mockResolvedValue({
      vp: 42,
      vp_by_strategy: [42],
      vp_state: 'final'
    } as any);
    jest.spyOn(snapshot.utils, 'validateSchema').mockReturnValue(true);

    const ctx: any = await verify(body(PROPOSAL, 1_700_000_000));
    expect(ctx.attestation.weight).toBe(42);
  });

  it('mints nothing for a public proposal', async () => {
    const ctx: any = await runVerify('', 1, 42);
    expect(ctx.attestation).toBeNull();
  });

  it('still refuses dust before it reaches minting', async () => {
    await expect(runVerify('shutter-elgamal', 100, 0.3)).rejects.toMatch(
      /voting power too low/
    );
  });
});
