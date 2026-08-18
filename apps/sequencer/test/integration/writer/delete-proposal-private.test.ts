/**
 * A private proposal becomes permanent when voting opens.
 *
 * "Cancel proposal" in the UI is a hard DELETE. Before voting starts that is
 * unremarkable — nothing has been cast. After it, the same action destroys ballots
 * people submitted under a guarantee that nobody could read them, which also means
 * nobody can check afterwards whether their vote was counted. So the record stops
 * being disposable at `start`, for everyone: author, moderator and admin alike.
 *
 * The cut-off is deliberately `start` rather than "while a tally is in flight". The
 * narrower rule would let a *published* confidential result be deleted again, which
 * is the outcome most worth protecting.
 *
 * All of it is gated on `privacy = 'shutter-elgamal'`; the public path is asserted
 * here too, because a rule this blunt is exactly the kind that leaks (D14).
 */

import * as actionHelper from '../../../src/helpers/actions';
import db, { sequencerDB } from '../../../src/helpers/mysql';
import { action, verify } from '../../../src/writer/delete-proposal';
import { spacesGetSpaceFixtures } from '../../fixtures/space';

const AUTHOR = '0xFC01614d28595d9ea5963daD9f44C0E0F0fE10f0';
const SPACE = 'test.eth';
const PAST = 1_600_000_000;
const FUTURE = Math.floor(Date.now() / 1e3) + 3600;

const getSpaceMock = jest.spyOn(actionHelper, 'getSpace');
getSpaceMock.mockResolvedValue(spacesGetSpaceFixtures);

function body(id: string, address = AUTHOR) {
  return {
    address,
    msg: JSON.stringify({ space: SPACE, payload: { proposal: id } })
  };
}

async function seed(id: string, privacy: string, start: number): Promise<void> {
  await db.queryAsync('DELETE FROM proposals WHERE id = ?', [id]);
  await db.queryAsync('INSERT INTO proposals SET ?', {
    id,
    ipfs: `bafkrei${id.slice(-12)}`,
    author: AUTHOR,
    created: 1,
    space: SPACE,
    network: '1',
    symbol: '',
    type: 'basic',
    strategies: '[]',
    validation: '{}',
    plugins: '{}',
    title: 'deletion fixture',
    body: '',
    discussion: '',
    choices: JSON.stringify(['Yes', 'No']),
    start,
    end: start + 100,
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

async function exists(id: string): Promise<boolean> {
  const rows = await db.queryAsync('SELECT id FROM proposals WHERE id = ?', [
    id
  ]);
  return rows.length > 0;
}

describe('delete-proposal: private proposals', () => {
  afterAll(async () => {
    await db.queryAsync('DELETE FROM proposals WHERE space = ?', [SPACE]);
    await db.endAsync();
    await sequencerDB.endAsync();
  });

  it('allows deleting a private proposal before voting starts', async () => {
    const id = '0xdel-private-future';
    await seed(id, 'shutter-elgamal', FUTURE);
    await expect(verify(body(id))).resolves.not.toThrow();
  });

  it('refuses once voting has started', async () => {
    const id = '0xdel-private-started';
    await seed(id, 'shutter-elgamal', PAST);
    await expect(verify(body(id))).rejects.toMatch(/cannot be deleted once/);
    expect(await exists(id)).toBe(true);
  });

  // The rule is about the ballots, not about who is asking. A moderator keeps
  // `flag-proposal` for content; what they lose is destroying the record.
  it('refuses a space admin too', async () => {
    const admin = (spacesGetSpaceFixtures as any).admins?.[0];
    if (!admin) throw new Error('fixture has no admin to test with');
    const id = '0xdel-private-admin';
    await seed(id, 'shutter-elgamal', PAST);
    await expect(verify(body(id, admin))).rejects.toMatch(
      /cannot be deleted once/
    );
  });

  // D14: the public path must behave exactly as it did before any of this.
  it('still allows deleting a public proposal after voting starts', async () => {
    const id = '0xdel-public-started';
    await seed(id, '', PAST);
    await expect(verify(body(id))).resolves.not.toThrow();
  });

  // No foreign keys exist, so nothing cascades. Without the explicit deletes these
  // rows outlive the proposal, keyed to an id that no longer resolves.
  it('removes the committee artifacts along with the proposal', async () => {
    const id = '0xdel-private-children';
    await seed(id, 'shutter-elgamal', FUTURE);
    await db.queryAsync('INSERT INTO te_results SET ?', {
      proposal_id: id,
      totals_json: '["1"]',
      keyper_indices: '[1,2]',
      bsgs_bound: '100',
      signature: `0x${'11'.repeat(65)}`,
      posted_at: 1
    });
    await db.queryAsync('INSERT INTO te_decryption_shares SET ?', {
      proposal_id: id,
      keyper_index: 1,
      candidate: 0,
      sigma: Buffer.alloc(96, 1),
      proof_e: Buffer.alloc(32, 1),
      proof_z: Buffer.alloc(32, 1),
      posted_at: 1
    });

    await action(body(id));

    expect(await exists(id)).toBe(false);
    for (const table of ['te_results', 'te_decryption_shares']) {
      const rows = await db.queryAsync(
        `SELECT proposal_id FROM ${table} WHERE proposal_id = ?`,
        [id]
      );
      expect({ table, orphans: rows.length }).toEqual({ table, orphans: 0 });
    }
  });
});
