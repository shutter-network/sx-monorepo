import snapshot from '@snapshot-labs/snapshot.js';
import { CB } from '../constants';
import { getProposal } from '../helpers/actions';
import {
  GegAttestationError,
  mintAttestation,
  verifyAttestation
} from '../helpers/gegAttestation';
import log from '../helpers/log';
import db from '../helpers/mysql';
import {
  isDustVotingPower,
  isWithinGegVotingWindow,
  verifyTeBallot
} from '../helpers/te';
import { deriveMaxWeight } from '../helpers/teCommittee';
import { captureError, hasStrategyOverride, jsonParse } from '../helpers/utils';
import { updateProposalAndVotes } from '../scores';

const scoreAPIUrl = process.env.SCORE_API_URL || 'https://score.snapshot.org';

// async function isLimitReached(space) {
//   const limit = 1500000;
//   const query = `SELECT COUNT(*) AS count FROM messages WHERE space = ? AND timestamp > (UNIX_TIMESTAMP() - 2592000)`;
//   const [{ count }] = await db.queryAsync(query, [space]);
//   return count > limit;
// }

export async function verify(body): Promise<any> {
  const msg = jsonParse(body.msg);

  const schemaIsValid = snapshot.utils.validateSchema(
    snapshot.schemas.vote,
    msg.payload
  );
  if (schemaIsValid !== true) {
    log.warn('[writer] Wrong vote format', schemaIsValid);
    return Promise.reject('wrong vote format');
  }

  const proposal = await getProposal(msg.space, msg.payload.proposal);
  if (!proposal) return Promise.reject('unknown proposal');

  const tsInt = (Date.now() / 1e3).toFixed();
  const msgTs = parseInt(msg.timestamp);
  if (
    msgTs > proposal.end ||
    proposal.start > msgTs ||
    tsInt > proposal.end ||
    proposal.start > tsInt
  )
    return Promise.reject('not in voting window');

  if (proposal.privacy === 'shutter') {
    if (msg.payload.reason)
      return Promise.reject('reason not allowed with shutter');
    if (
      typeof msg.payload.choice !== 'string' ||
      !msg.payload.choice.startsWith('0x')
    )
      return Promise.reject('invalid choice');
  } else if (proposal.privacy === 'shutter-elgamal') {
    // The committee re-checks the voting window at tally time against the frozen
    // config, and its window is half-open where Snapshot's is closed. Adopt geg's
    // boundary here so a vote cannot be accepted now and excluded then — see
    // helpers/te.ts for what that costs and why the alternative is worse.
    if (!isWithinGegVotingWindow(msgTs, proposal.start, proposal.end)) {
      return Promise.reject('not in voting window');
    }
    if (msg.payload.reason)
      return Promise.reject('reason not allowed with shutter-elgamal');
    // The voter ships the encrypted ballot as a JSON object under
    // ``choice`` (the same shape ``buildBallot`` produces in the SDK,
    // serialised with all bytes as 0x-hex). Verify it now so we never
    // persist a ciphertext the tally would later reject. See
    // helpers/te.ts for the auth model.
    if (typeof msg.payload.choice !== 'object' || msg.payload.choice === null) {
      return Promise.reject('invalid choice: expected ballot object');
    }
    const choiceJson = JSON.stringify(msg.payload.choice);
    const result = await verifyTeBallot(
      proposal,
      body.address.toLowerCase(),
      choiceJson
    );
    if (!result.ok) {
      return Promise.reject(`invalid private ballot: ${result.reason}`);
    }
  } else {
    if (
      !snapshot.utils.voting[proposal.type].isValidChoice(
        msg.payload.choice,
        proposal.choices
      )
    )
      return Promise.reject('invalid choice');
  }

  if (proposal.validation?.name && proposal.validation.name !== 'any') {
    try {
      const {
        validation: { name: validationName, params: validationParams }
      } = proposal;
      if (validationName === 'basic')
        validationParams.strategies =
          validationParams.strategies ?? proposal.strategies;

      const validate = await snapshot.utils.validate(
        validationName,
        body.address,
        msg.space,
        proposal.network,
        proposal.snapshot,
        validationParams,
        { url: scoreAPIUrl }
      );
      if (!validate) return Promise.reject('failed vote validation');
    } catch (err) {
      captureError(
        err,
        { contexts: { input: { space: msg.space, address: body.address } } },
        [504]
      );
      log.warn(
        `[writer] Failed to check vote validation, ${msg.space}, ${body.address}, ${JSON.stringify(
          err
        )}`
      );
      return Promise.reject('failed to check vote validation');
    }
  }

  let vp: any = {};
  try {
    vp = await snapshot.utils.getVp(
      body.address,
      proposal.network,
      proposal.strategies,
      proposal.snapshot,
      msg.space,
      false,
      { url: scoreAPIUrl }
    );
    if (vp.vp === 0) return Promise.reject('no voting power');
    // Private ballots are weighted by an integer, so anything under 0.5 would be
    // counted as zero and dropped from the feed without ever reaching the
    // committee. Refuse it here so the voter is told, rather than shown a cast
    // vote that silently does not count.
    if (proposal.privacy === 'shutter-elgamal' && isDustVotingPower(vp.vp)) {
      return Promise.reject(
        'voting power too low for a private proposal, must be at least 0.5'
      );
    }
  } catch (err: any) {
    captureError(
      err,
      { contexts: { input: { space: msg.space, address: body.address } } },
      [504]
    );
    log.warn(
      `[writer] Failed to check voting power (vote), ${msg.space}, ${body.address}, ${
        proposal.snapshot
      }, ${JSON.stringify(err)}`
    );
    return Promise.reject('failed to check voting power');
  }

  // if (await isLimitReached(msg.space)) return Promise.reject('too much activity, please contact an admin');

  // Mint the eligibility credential here, not on the hub's read path.
  //
  // The credential binds this ballot's weight for the committee, and the weight
  // comes from `vp` — which the sequencer computed a few lines up. Signing it
  // here puts the signature with the component that made the claim, and takes
  // ~2ms of BLS off an unauthenticated public GET (finding M2).
  //
  // Safe to fix the weight now because a private proposal cannot be edited once
  // voting opens (`update-proposal` rejects `proposal.start < now`), so `budget`
  // and therefore `maxWeight` are already final, and `votes.vp` is never
  // recomputed for a private proposal.
  let attestation: TeAttestation | null = null;
  if (proposal.privacy === 'shutter-elgamal') {
    try {
      attestation = await mintBallotAttestation(proposal, msg, vp.vp);
    } catch (err: any) {
      if (err instanceof GegAttestationError) {
        log.warn(`[writer] cannot mint credential: ${err.message}`);
        return Promise.reject(`private voting unavailable: ${err.message}`);
      }
      throw err;
    }
  }

  return { proposal, vp, attestation };
}

export interface TeAttestation {
  weight: number;
  nonce: number;
  signature: string;
}

async function mintBallotAttestation(
  proposal: any,
  msg: any,
  vp: number
): Promise<TeAttestation> {
  // `getProposal` already parses this column (helpers/actions.ts), so it arrives
  // as an object — parsing it again turns it into the string "[object Object]"
  // and yields no budget at all. Both shapes are accepted so a caller that hands
  // over a raw row still works.
  const teConfig =
    typeof proposal.te_config === 'string'
      ? jsonParse(proposal.te_config, null)
      : proposal.te_config;
  const budget = Number(teConfig?.budget);
  if (!Number.isInteger(budget) || budget < 1) {
    throw new GegAttestationError(
      `proposal ${proposal.id} has no usable ballot budget`
    );
  }
  const maxWeight = BigInt(deriveMaxWeight(budget));

  // The same clamp the verify panel applies and the committee enforces. `vp` has
  // already cleared the dust floor, so the rounded value is at least 1.
  const rounded = BigInt(Math.round(vp));
  const weight = rounded > maxWeight ? maxWeight : rounded;

  // The vote's own timestamp, which becomes `votes.created`. The protocol ranks
  // duplicate ballots by `(nonce, sequenceNumber)` under a last-wins policy —
  // Snapshot's "newer vote wins" rule expressed in the committee's terms.
  const nonce = BigInt(parseInt(msg.timestamp));
  const envelope = jsonParse(JSON.stringify(msg.payload.choice), null);

  const args = {
    electionId: proposal.id,
    pseudonym: envelope?.pseudonym,
    vk: envelope?.vk,
    weight,
    nonce
  };
  const signature = await mintAttestation(args);

  // Verify what we just signed. Not distrust of our own key — the same rule as
  // the dust floor and the window boundary: do not accept what the committee
  // will drop. A framing or encoding slip would otherwise be stored, shown to
  // the voter as a cast vote, and excluded at tally as INVALID_ATTESTATION.
  if (!(await verifyAttestation({ ...args, signature, maxWeight }))) {
    throw new GegAttestationError(
      'freshly minted credential failed verification'
    );
  }

  return {
    weight: Number(weight),
    nonce: Number(nonce),
    signature
  };
}

export async function action(body, ipfs, receipt, id, context): Promise<void> {
  const msg = jsonParse(body.msg);
  const voter = body.address;
  const created = parseInt(msg.timestamp);
  const choice = JSON.stringify(msg.payload.choice);
  const metadata = JSON.stringify(msg.payload.metadata || {});
  const app = msg.payload.app;
  const reason = msg.payload.reason || '';
  const proposalId = msg.payload.proposal;

  // Check if voting power is final
  let vpState = context.vp.vp_state;
  const withOverride = hasStrategyOverride(context.proposal.strategies);
  if (vpState === 'final' && withOverride) vpState = 'pending';

  const params = {
    id,
    ipfs,
    voter,
    created,
    space: msg.space,
    proposal: proposalId,
    choice,
    metadata,
    reason,
    app,
    vp: context.vp.vp,
    vp_by_strategy: JSON.stringify(context.vp.vp_by_strategy),
    vp_state: vpState,
    vp_value: 0,
    cb: CB.PENDING_COMPUTE,
    // NULL on every public proposal. On a private one these are the credential
    // the committee verifies, stored on the vote row rather than in a side table
    // so they are written in the same statement as the vote — a vote that exists
    // without its credential is a ballot the hub's feed cannot serve, which
    // stalls the whole tally.
    te_weight: context.attestation?.weight ?? null,
    te_nonce: context.attestation?.nonce ?? null,
    te_attestation: context.attestation?.signature ?? null
  };

  // Check if voter already voted
  const votes = await db.queryAsync(
    'SELECT id, created FROM votes WHERE voter = ? AND proposal = ? AND space = ? ORDER BY created DESC LIMIT 1',
    [voter, proposalId, msg.space]
  );

  // Reject vote with later timestamp
  if (votes[0]) {
    if (votes[0].created > parseInt(msg.timestamp)) {
      return Promise.reject('already voted at later time');
    } else if (votes[0].created === parseInt(msg.timestamp)) {
      const localCompare = id.localeCompare(votes[0].id);
      if (localCompare <= 0)
        return Promise.reject('already voted same time with lower index');
    }
    // Update previous vote
    log.info(`[writer] Update previous vote, ${voter}, ${proposalId}`);
    await db.queryAsync(
      `
      UPDATE votes
      SET id = ?, ipfs = ?, created = ?, choice = ?, reason = ?, metadata = ?, app = ?, vp = ?, vp_by_strategy = ?, vp_state = ?, te_weight = ?, te_nonce = ?, te_attestation = ?
      WHERE voter = ? AND proposal = ? AND space = ?;
      UPDATE leaderboard SET last_vote = ? WHERE user = ? AND space = ? LIMIT 1;
    `,
      [
        id,
        ipfs,
        created,
        choice,
        reason,
        metadata,
        app,
        params.vp,
        params.vp_by_strategy,
        params.vp_state,
        // Overwritten, not left behind: `created` changes on a re-vote, so the
        // previous credential's nonce is stale. Carrying them in the same
        // statement is why a re-vote cannot orphan a credential.
        params.te_weight,
        params.te_nonce,
        params.te_attestation,
        voter,
        proposalId,
        msg.space,
        created,
        voter,
        msg.space
      ]
    );
  } else {
    // Store vote in dedicated table
    await db.queryAsync(
      `
        INSERT INTO votes SET ?;
        INSERT INTO leaderboard (space, user, vote_count, last_vote, vp_value)
          VALUES(?, ?, 1, ?, 0)
          ON DUPLICATE KEY UPDATE vote_count = vote_count + 1, last_vote = ?;
        UPDATE spaces SET vote_count = vote_count + 1 WHERE id = ?;
      `,
      [params, msg.space, voter, created, created, msg.space]
    );
  }

  // Update proposal scores and voters vp
  try {
    const result = await updateProposalAndVotes(proposalId);
    if (!result)
      log.warn(`[writer] updateProposalAndVotes() false, ${proposalId}`);
  } catch (err: any) {
    captureError(
      err,
      { contexts: { input: { space: msg.space, id: proposalId } } },
      [504]
    );
    log.warn(
      `[writer] updateProposalAndVotes() failed, ${msg.space}, ${proposalId}`
    );
  }
}
