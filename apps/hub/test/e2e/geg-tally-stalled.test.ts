/**
 * The stall lifecycle, and the split that makes it mean something.
 *
 * A stalled tally is one the committee could not complete — a quorum that never
 * formed, or an election too large to recover inside the coordinator's attempt
 * budget. The flag exists so that state is *persisted* rather than living in the
 * coordinator's memory, and the two directions are deliberately signed by
 * different identities:
 *
 *   - the coordinator marks the stall, because it is the only party that knows
 *     it has run out of attempts;
 *   - the admin clears it.
 *
 * Collapsing that into one authority would make a restart clear the stall by
 * accident: the retry budget is in-memory, so a fresh coordinator sees the
 * election, tries again, and stalls again — looping quietly instead of waiting
 * for a human. These tests pin the split from both sides, including the case
 * that matters most: the coordinator's own signature must not resume.
 */

import { Wallet } from '@ethersproject/wallet';
import fetch from 'node-fetch';
import { eligibilityPublicKey } from '../../src/helpers/gegAttestation';
import { requestDigest } from '../../src/helpers/gegDigests';
import db from '../../src/helpers/mysql';

const HOST = `http://localhost:${process.env.PORT || 3030}`;

const PUBLISHER = new Wallet(`0x${'a1'.repeat(32)}`);
const ADMIN = new Wallet(`0x${'b2'.repeat(32)}`);
const KEYPER = new Wallet(`0x${'c3'.repeat(32)}`);
// Distinct from ADMIN on purpose: the author is only the *fallback* authority, so a
// fixture where they are the same address cannot tell the two rules apart.
const AUTHOR = new Wallet(`0x${'e5'.repeat(32)}`);

const ID = '0xbbbb000000000000000000000000000000000000000000000000000000000001';

async function sign(wallet: Wallet, op: string) {
  return wallet.signMessage(requestDigest(op, ID));
}

async function post(body: unknown) {
  const res = await fetch(`${HOST}/api/proposal/${ID}/te_tally_stalled`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });
  return res.status;
}

async function stalledFlag(): Promise<number> {
  const [row] = await db.queryAsync(
    'SELECT te_tally_stalled FROM proposals WHERE id = ?',
    [ID]
  );
  return Number(row.te_tally_stalled);
}

async function reportedByElectionRead(): Promise<boolean> {
  const res = await fetch(`${HOST}/api/proposal/${ID}/te_geg_election`);
  return (await res.json()).tallyStalled;
}

describe('POST /api/proposal/:id/te_tally_stalled', () => {
  beforeAll(async () => {
    // The resume authority is the proposal's space admins, read live.
    await db.queryAsync('DELETE FROM spaces WHERE id = ?', ['test.eth']);
    await db.queryAsync('INSERT INTO spaces SET ?', {
      id: 'test.eth',
      name: 'Stall fixture space',
      settings: JSON.stringify({ admins: [ADMIN.address] }),
      verified: 0,
      deleted: 0,
      flagged: 0,
      hibernated: 0,
      turbo_expiration: 0,
      proposal_count: 0,
      vote_count: 0,
      follower_count: 0,
      created: 1,
      updated: 1
    });
    // The frozen key has to be the one the hub actually holds: the election read
    // asserts they match and 503s otherwise, which would look like a stall bug.
    const eligibilityKey = await eligibilityPublicKey();
    await db.queryAsync('DELETE FROM proposals WHERE id = ?', [ID]);
    await db.queryAsync('INSERT INTO proposals SET ?', {
      id: ID,
      ipfs: 'bafkreistallfixture',
      author: AUTHOR.address,
      created: 1,
      space: 'test.eth',
      network: '1',
      symbol: '',
      type: 'weighted',
      strategies: '[]',
      validation: '{}',
      plugins: '{}',
      title: 'stall lifecycle',
      body: '',
      discussion: '',
      choices: JSON.stringify(['Yes', 'No']),
      start: 1,
      end: 2,
      quorum: 0,
      privacy: 'shutter-elgamal',
      snapshot: 1,
      app: '',
      scores: '[]',
      scores_by_strategy: '[]',
      scores_state: 'pending',
      scores_total: 0,
      scores_updated: 0,
      vp_value_by_strategy: '[]',
      votes: 0,
      te_geg_config: JSON.stringify({
        v: 1,
        keypers: [{ address: KEYPER.address, url: 'https://k1.example' }],
        thresholdT: 1,
        thresholdN: 1,
        eligibilityKey,
        resultPublisherAddress: PUBLISHER.address,
        adminAddress: ADMIN.address,
        votingStart: 1,
        votingEnd: 2,
        weightedBudget: 100
      })
    });
  });

  afterAll(async () => {
    await db.queryAsync('DELETE FROM spaces WHERE id = ?', ['test.eth']);
    await db.queryAsync('DELETE FROM proposals WHERE id = ?', [ID]);
    await db.endAsync();
  });

  beforeEach(async () => {
    await db.queryAsync(
      'UPDATE proposals SET te_tally_stalled = 0 WHERE id = ?',
      [ID]
    );
  });

  it('lets the coordinator mark a stall', async () => {
    expect(
      await post({
        stalled: true,
        resultPublisherSig: await sign(PUBLISHER, 'tally_stall')
      })
    ).toBe(204);
    expect(await stalledFlag()).toBe(1);
    expect(await reportedByElectionRead()).toBe(true);
  });

  it('lets the admin clear one', async () => {
    await post({
      stalled: true,
      resultPublisherSig: await sign(PUBLISHER, 'tally_stall')
    });
    expect(
      await post({
        stalled: false,
        adminSig: await sign(ADMIN, 'tally_resume')
      })
    ).toBe(204);
    expect(await stalledFlag()).toBe(0);
    expect(await reportedByElectionRead()).toBe(false);
  });

  // The property the whole split exists for. A coordinator restart re-signs
  // whatever it can; if that included a resume, a stalled election would clear
  // itself and loop.
  it('refuses a resume signed by the coordinator', async () => {
    await post({
      stalled: true,
      resultPublisherSig: await sign(PUBLISHER, 'tally_stall')
    });
    expect(
      await post({
        stalled: false,
        adminSig: await sign(PUBLISHER, 'tally_resume')
      })
    ).toBe(403);
    expect(await stalledFlag()).toBe(1); // still stalled
  });

  it('refuses a stall signed by the admin', async () => {
    expect(
      await post({
        stalled: true,
        resultPublisherSig: await sign(ADMIN, 'tally_stall')
      })
    ).toBe(403);
    expect(await stalledFlag()).toBe(0);
  });

  it('refuses either direction from a committee member', async () => {
    expect(
      await post({
        stalled: true,
        resultPublisherSig: await sign(KEYPER, 'tally_stall')
      })
    ).toBe(403);
    expect(
      await post({
        stalled: false,
        adminSig: await sign(KEYPER, 'tally_resume')
      })
    ).toBe(403);
  });

  // The direction is inside the signed message, so a signature taken for one
  // direction cannot be presented as the other.
  it('refuses a stall signature replayed as a resume', async () => {
    await post({
      stalled: true,
      resultPublisherSig: await sign(PUBLISHER, 'tally_stall')
    });
    expect(
      await post({
        stalled: false,
        adminSig: await sign(ADMIN, 'tally_stall')
      })
    ).toBe(403);
    expect(await stalledFlag()).toBe(1);
  });

  // The authority is live, so adding an admin grants it immediately — this is the
  // case a frozen list gets wrong: an admin appointed after the proposal was made
  // could not revive it.
  it('lets an admin added after the proposal was created clear it', async () => {
    const LATE = new Wallet(`0x${'d4'.repeat(32)}`);
    await db.queryAsync('UPDATE spaces SET settings = ? WHERE id = ?', [
      JSON.stringify({ admins: [ADMIN.address, LATE.address] }),
      'test.eth'
    ]);
    await post({
      stalled: true,
      resultPublisherSig: await sign(PUBLISHER, 'tally_stall')
    });
    expect(
      await post({ stalled: false, adminSig: await sign(LATE, 'tally_resume') })
    ).toBe(204);
    await db.queryAsync('UPDATE spaces SET settings = ? WHERE id = ?', [
      JSON.stringify({ admins: [ADMIN.address] }),
      'test.eth'
    ]);
  });

  // And removing one revokes it, which a frozen list also gets wrong.
  it('refuses an admin who has since been removed from the space', async () => {
    await db.queryAsync('UPDATE spaces SET settings = ? WHERE id = ?', [
      JSON.stringify({ admins: [] }),
      'test.eth'
    ]);
    await post({
      stalled: true,
      resultPublisherSig: await sign(PUBLISHER, 'tally_stall')
    });
    // The author is the fallback, and ADMIN is not the author.
    expect(
      await post({
        stalled: false,
        adminSig: await sign(ADMIN, 'tally_resume')
      })
    ).toBe(403);
    expect(await stalledFlag()).toBe(1);
    await db.queryAsync('UPDATE spaces SET settings = ? WHERE id = ?', [
      JSON.stringify({ admins: [ADMIN.address] }),
      'test.eth'
    ]);
  });

  // A space with no admins must not leave a stall unrecoverable.
  it('falls back to the proposal author when the space lists no admins', async () => {
    await db.queryAsync('UPDATE spaces SET settings = ? WHERE id = ?', [
      JSON.stringify({ admins: [] }),
      'test.eth'
    ]);
    await post({
      stalled: true,
      resultPublisherSig: await sign(PUBLISHER, 'tally_stall')
    });
    expect(
      await post({
        stalled: false,
        adminSig: await sign(AUTHOR, 'tally_resume')
      })
    ).toBe(204);
    await db.queryAsync('UPDATE spaces SET settings = ? WHERE id = ?', [
      JSON.stringify({ admins: [ADMIN.address] }),
      'test.eth'
    ]);
  });

  it('rejects a missing or non-boolean direction', async () => {
    expect(
      await post({ resultPublisherSig: await sign(PUBLISHER, 'tally_stall') })
    ).toBe(400);
    expect(
      await post({
        stalled: 'yes',
        resultPublisherSig: await sign(PUBLISHER, 'tally_stall')
      })
    ).toBe(400);
  });
});
