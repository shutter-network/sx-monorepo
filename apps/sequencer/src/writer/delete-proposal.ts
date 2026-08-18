import { CB } from '../constants';
import { getProposal, getSpace } from '../helpers/actions';
import db from '../helpers/mysql';
import { jsonParse } from '../helpers/utils';

export async function verify(body): Promise<any> {
  const msg = jsonParse(body.msg);
  const proposal = await getProposal(msg.space, msg.payload.proposal);
  if (!proposal) return Promise.reject('unknown proposal');

  const space = await getSpace(msg.space);
  const admins = (space?.admins || []).map(admin => admin.toLowerCase());
  const mods = (space?.moderators || []).map(mod => mod.toLowerCase());
  if (
    !admins.includes(body.address.toLowerCase()) &&
    !mods.includes(body.address.toLowerCase()) &&
    proposal.author.toLowerCase() !== body.address.toLowerCase()
  )
    return Promise.reject('not authorized to archive proposal');

  // A private proposal becomes permanent the moment voting opens. It cannot be deleted.
  // Gated on privacy.
  if (proposal.privacy === 'shutter-elgamal') {
    const now = Math.floor(Date.now() / 1e3);
    if (now >= proposal.start) {
      return Promise.reject(
        'a private proposal cannot be deleted once voting has started'
      );
    }
  }
}

export async function action(body): Promise<void> {
  const msg = jsonParse(body.msg);
  const proposal = await getProposal(msg.space, msg.payload.proposal);
  const id = msg.payload.proposal;

  // The te_* children have no foreign key and so no cascade: without these they
  // outlive the proposal, keyed to an id that no longer resolves. They are no-ops
  // for a public proposal, which never has any.
  const queries = `
    DELETE FROM proposals WHERE id = ? LIMIT 1;
    DELETE FROM te_dkg_submissions WHERE proposal_id = ?;
    DELETE FROM te_aggregate_submissions WHERE proposal_id = ?;
    DELETE FROM te_decryption_shares WHERE proposal_id = ?;
    DELETE FROM te_results WHERE proposal_id = ?;
    UPDATE votes SET cb = ? WHERE proposal = ?;
    UPDATE leaderboard
      SET proposal_count = GREATEST(proposal_count - 1, 0)
      WHERE user = ? AND space = ?
      LIMIT 1;
    UPDATE spaces
      SET proposal_count = GREATEST(proposal_count - 1, 0)
      WHERE id = ?;
  `;

  await db.queryAsync(queries, [
    id,
    id,
    id,
    id,
    id,
    CB.PENDING_DELETE,
    id,
    proposal.author,
    msg.space,
    msg.space
  ]);
}
