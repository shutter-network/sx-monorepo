import snapshot from '@snapshot-labs/snapshot.js';
import { CB } from './constants';
import log from './helpers/log';
import db from './helpers/mysql';
import { getDecryptionKey } from './helpers/shutter';
import {
  aggregateBallots,
  aggregateToJson,
  decodeCommitteePks,
  recoverTeTally,
  shareRowsToShares,
  triggerKeypers
} from './helpers/te';
import { hasStrategyOverride, sha256 } from './helpers/utils';

const scoreAPIUrl = process.env.SCORE_API_URL || 'https://score.snapshot.org';
const FINALIZE_SCORE_SECONDS_DELAY = 60;

async function getProposal(id: string): Promise<any | undefined> {
  const query = 'SELECT * FROM proposals WHERE id = ? LIMIT 1';
  const [proposal] = await db.queryAsync(query, [id]);
  if (!proposal) return;
  proposal.strategies = JSON.parse(proposal.strategies);
  proposal.plugins = JSON.parse(proposal.plugins);
  proposal.choices = JSON.parse(proposal.choices);
  proposal.scores = JSON.parse(proposal.scores);
  proposal.scores_by_strategy = JSON.parse(proposal.scores_by_strategy);
  proposal.vp_value_by_strategy = JSON.parse(proposal.vp_value_by_strategy);
  // Threshold-ElGamal columns: NULL when privacy != 'shutter-elgamal' or
  // before DKG completion. Parse JSON fields and hex-encode the binary mpk
  // so downstream callers see the same shape as actions.ts/getProposal.
  if (typeof proposal.te_config === 'string')
    proposal.te_config = JSON.parse(proposal.te_config);
  if (typeof proposal.te_committee_pks === 'string')
    proposal.te_committee_pks = JSON.parse(proposal.te_committee_pks);
  if (typeof proposal.te_keyper_urls === 'string')
    proposal.te_keyper_urls = JSON.parse(proposal.te_keyper_urls);
  if (typeof proposal.te_aggregate === 'string')
    proposal.te_aggregate = JSON.parse(proposal.te_aggregate);
  if (proposal.te_mpk && Buffer.isBuffer(proposal.te_mpk))
    proposal.te_mpk = '0x' + proposal.te_mpk.toString('hex');
  let proposalState = 'pending';
  const ts = parseInt((Date.now() / 1e3).toFixed());
  if (ts > proposal.start) proposalState = 'active';
  if (ts > proposal.end) proposalState = 'closed';
  proposal.state = proposalState;
  return proposal;
}

async function getVotes(proposalId: string): Promise<any[] | undefined> {
  const query =
    'SELECT id, choice, voter, vp, vp_by_strategy, vp_state, vp_value FROM votes WHERE proposal = ?';
  const votes = await db.queryAsync(query, [proposalId]);

  return votes.map(vote => {
    vote.choice = JSON.parse(vote.choice);
    vote.vp_by_strategy = JSON.parse(vote.vp_by_strategy);
    vote.balance = vote.vp;
    vote.scores = vote.vp_by_strategy;
    return vote;
  });
}

async function updateVotesVp(
  votes: any[],
  vpState: string,
  proposalId: string
) {
  const votesWithChange = votes.filter(vote => {
    const key1 = sha256(JSON.stringify([vote.balance, vote.scores, vpState]));
    const key2 = sha256(
      JSON.stringify([vote.vp, vote.vp_by_strategy, vote.vp_state])
    );
    return key1 !== key2;
  });
  if (votesWithChange.length === 0) return;

  const max = 200;
  const pages = Math.ceil(votesWithChange.length / max);
  const votesInPages: any = [];
  Array.from(Array(pages)).forEach((x, i) => {
    votesInPages.push(votesWithChange.slice(max * i, max * (i + 1)));
  });

  let i = 0;
  for (const votesInPage of votesInPages) {
    const params: any = [];
    let query = '';
    votesInPage.forEach((vote: any) => {
      query += `UPDATE votes
      SET vp = ?, vp_by_strategy = ?, vp_state = ?, vp_value = ?, cb = ?
      WHERE id = ? AND proposal = ? AND cb != ? LIMIT 1; `;
      params.push(vote.balance);
      params.push(JSON.stringify(vote.scores));
      params.push(vpState);
      params.push(vote.vp_value);
      params.push(CB.PENDING_COMPUTE);
      params.push(vote.id);
      params.push(proposalId);
      params.push(CB.PENDING_DELETE);
    });
    await db.queryAsync(query, params);
    if (i) await snapshot.utils.sleep(200);
    i++;
  }
  log.info(
    `[scores] updated votes vp, ${votesWithChange.length}/${votes.length} on ${proposalId}`
  );
}

async function updateProposalScores(proposal: any, scores: any, votes: number) {
  const ts = (Date.now() / 1e3).toFixed();
  const query = `
    UPDATE proposals
    SET scores_state = ?,
    scores = ?,
    scores_by_strategy = ?,
    scores_total = ?,
    scores_updated = ?,
    votes = ?,
    cb = ?
    WHERE id = ? LIMIT 1;
  `;
  await db.queryAsync(query, [
    scores.scores_state,
    JSON.stringify(scores.scores),
    JSON.stringify(scores.scores_by_strategy),
    scores.scores_total,
    ts,
    votes,
    proposal.cb === CB.PENDING_FINAL ? CB.PENDING_COMPUTE : proposal.cb,
    proposal.id
  ]);
}

const pendingRequests = {};

export async function updateProposalAndVotes(
  proposalId: string,
  force = false
) {
  const proposal = await getProposal(proposalId);
  if (!proposal || proposal.state === 'pending') return false;
  if (proposal.scores_state === 'final') return true;

  if (!force && proposal.privacy === 'shutter' && proposal.state === 'closed') {
    await getDecryptionKey(proposal.id);
    return true;
  }

  if (proposal.privacy === 'shutter-elgamal') {
    if (proposal.state !== 'closed') return false;
    const finalised = await runShutterElgamalTally(proposal);
    return finalised;
  }

  const ts = Number((Date.now() / 1e3).toFixed());

  // Delay computation of final scores, to allow time for last minute votes to finish
  // up to 1 minute after the end of the proposal
  if (proposal.end <= ts) {
    const secondsSinceEnd = ts - proposal.end;
    await snapshot.utils.sleep(
      Math.max(FINALIZE_SCORE_SECONDS_DELAY - secondsSinceEnd, 0) * 1000
    );
  }

  // Ignore score calculation if proposal have more than 100k votes and scores_updated greater than 5 minute
  if (
    (proposal.votes > 20000 && proposal.scores_updated > ts - 300) ||
    pendingRequests[proposalId]
  ) {
    console.log(
      'ignore score calculation',
      proposal.space,
      proposalId,
      proposal.votes,
      proposal.scores_updated
    );
    return false;
  }
  if (proposal.votes > 20000) pendingRequests[proposalId] = true;

  try {
    // Get votes
    let votes: any = await getVotes(proposalId);
    const isFinal = votes.every(vote => vote.vp_state === 'final');
    let vpState = 'final';

    if (!isFinal) {
      log.info(`[scores] Get scores', ${proposalId}`);

      // Get scores
      const { scores, state } = await snapshot.utils.getScores(
        proposal.space,
        proposal.strategies,
        proposal.network,
        votes.map(vote => vote.voter),
        parseInt(proposal.snapshot),
        scoreAPIUrl,
        { returnValue: 'all' }
      );
      vpState = state;

      // Add vp to votes
      votes = votes.map((vote: any) => {
        vote.scores = proposal.strategies.map(
          (strategy, i) => scores[i][vote.voter] || 0
        );
        vote.balance = vote.scores.reduce((a, b: any) => a + b, 0);
        return vote;
      });
    }

    // Get results
    const voting = new snapshot.utils.voting[proposal.type](
      proposal,
      votes,
      proposal.strategies
    );
    const results = {
      scores_state: proposal.state === 'closed' ? 'final' : 'pending',
      scores: voting.getScores(),
      scores_by_strategy: voting.getScoresByStrategy(),
      scores_total: voting.getScoresTotal()
    };

    // Check if voting power is final
    const withOverride = hasStrategyOverride(proposal.strategies);
    if (vpState === 'final' && withOverride && proposal.state !== 'closed')
      vpState = 'pending';

    // Update votes voting power
    if (!isFinal) await updateVotesVp(votes, vpState, proposalId);

    // Store scores
    await updateProposalScores(proposal, results, votes.length);
    log.info(
      `[scores] Proposal updated ${proposal.id}, ${proposal.space}, ${results.scores_state}, ${votes.length}`
    );

    delete pendingRequests[proposalId];
    return true;
  } catch (err) {
    delete pendingRequests[proposalId];
    throw err;
  }
}

/**
 * Threshold-ElGamal tally worker.
 *
 * Idempotent. Called by ``updateProposalAndVotes`` once the proposal has
 * closed. Each invocation:
 *
 *   1. Recomputes the vp-weighted homomorphic aggregate from the verified
 *      ballots in the votes table and persists it as ``proposals.te_aggregate``.
 *      Hub serves this JSON to keypers via ``GET /api/proposal/:id/te_aggregate``.
 *   2. Pings every keyper URL so they re-pull the aggregate and submit\n *      shares (no-op for keypers that already submitted: hub side is\n *      ``INSERT IGNORE`` on PK ``(proposal, keyper, candidate)``).\n *   3. Reads back the share rows; if any candidate still has fewer than\n *      ``t+1`` valid shares, returns ``false`` and leaves ``scores_state``\n *      pending — the next scheduler tick will retry.\n *   4. Otherwise calls ``recoverTally`` (Lagrange + BSGS), writes the\n *      integer per-candidate totals into ``proposals.scores`` and marks\n *      the proposal final.\n *\n * ``scores_by_strategy`` is intentionally empty: per-voter strategy\n * breakdown leaks individual votes through homomorphic isolation, which\n * is the exact privacy property this mode preserves.\n */\nasync function runShutterElgamalTally(proposal: any): Promise<boolean> {\n  if (!proposal.te_config) {\n    log.warn(`[te-tally] ${proposal.id} missing te_config`);\n    return false;\n  }\n  const numCandidates: number = proposal.te_config.numCandidates;\n  const threshold: number = proposal.te_threshold_t;\n  const keyperUrls: string[] = proposal.te_keyper_urls || [];\n  const committeePks: string[] = proposal.te_committee_pks || [];\n  if (!proposal.te_mpk || keyperUrls.length === 0 || committeePks.length === 0) {\n    log.warn(`[te-tally] ${proposal.id} DKG not finalised`);\n    return false;\n  }\n\n  // Pull every persisted ballot. Each row in ``votes.choice`` has been\n  // ``verifyBallot``-validated at write time (see helpers/te.ts), so we\n  // do not re-verify here; the homomorphic sum is over trusted inputs.\n  const rawVotes = await db.queryAsync(\n    'SELECT choice, vp FROM votes WHERE proposal = ? AND cb != ?',\n    [proposal.id, CB.PENDING_DELETE]\n  );\n  if (rawVotes.length === 0) {\n    // No votes: write empty tally and finalise. recoverTally would throw\n    // on zero candidates of zero ballots, so short-circuit.\n    const zeroScores = new Array(numCandidates).fill(0);\n    await updateProposalScores(\n      proposal,\n      {\n        scores_state: 'final',\n        scores: zeroScores,\n        scores_by_strategy: [],\n        scores_total: 0\n      },\n      0\n    );\n    return true;\n  }\n\n  let aggregate;\n  try {\n    aggregate = aggregateBallots(numCandidates, rawVotes);\n  } catch (err: any) {\n    log.warn(`[te-tally] ${proposal.id} aggregate failed: ${err.message}`);\n    return false;\n  }\n  const aggregateJson = aggregateToJson(proposal.id, aggregate);\n  await db.queryAsync(\n    'UPDATE proposals SET te_aggregate = ? WHERE id = ? LIMIT 1',\n    [JSON.stringify(aggregateJson), proposal.id]\n  );\n\n  // Nudge keypers; they may already be done.\n  await triggerKeypers(proposal.id, keyperUrls);\n\n  // Read shares. Each (keyper, candidate) row is one PartialDecryption.\n  const shareRows = await db.queryAsync(\n    'SELECT keyper_index, candidate, sigma, proof_e, proof_z FROM te_decryption_shares WHERE proposal_id = ?',\n    [proposal.id]\n  );\n  const { shares, warnings } = shareRowsToShares(shareRows, numCandidates);\n  for (const w of warnings) log.warn(`[te-tally] ${proposal.id} ${w}`);\n\n  const need = threshold + 1;\n  for (let j = 0; j < numCandidates; j++) {\n    if (shares[j].length < need) {\n      log.info(\n        `[te-tally] ${proposal.id} candidate ${j} has ${shares[j].length}/${need} shares; waiting`\n      );\n      return false;\n    }\n  }\n\n  // Upper bound for BSGS table sizing. Each ballot contributes vp · 1 per\n  // chosen candidate (Variant A exact B=1), so the maximum tally is the\n  // sum of all voting power. Add a safety pad of 1 for empty-vote edge.\n  let totalVp = 0n;\n  for (const v of rawVotes) totalVp += BigInt(Math.round(v.vp));\n  const upperBound = totalVp > 0n ? totalVp : 1n;\n\n  let scores: bigint[];\n  try {\n    const committeePKs = decodeCommitteePks(committeePks);\n    scores = await recoverTeTally(\n      proposal.id,\n      aggregate,\n      shares,\n      threshold,\n      committeePKs,\n      upperBound\n    );\n  } catch (err: any) {\n    log.warn(`[te-tally] ${proposal.id} recover failed: ${err.message}`);\n    return false;\n  }\n\n  const numericScores = scores.map(s => Number(s));\n  const total = numericScores.reduce((a, b) => a + b, 0);\n  await updateProposalScores(\n    proposal,\n    {\n      scores_state: 'final',\n      scores: numericScores,\n      scores_by_strategy: [],\n      scores_total: total\n    },\n    rawVotes.length\n  );\n  log.info(\n    `[te-tally] ${proposal.id} finalised; scores=${JSON.stringify(numericScores)}`\n  );\n  return true;\n}\n