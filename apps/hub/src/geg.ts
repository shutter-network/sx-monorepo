/**
 * Read endpoints serving Snapshot state in the threshold protocol's own shapes.
 *
 * The keypers and their coordinator run from a separate codebase and speak one
 * fixed data-layer contract. A translator service maps that contract onto these
 * endpoints; this router is where Snapshot's schema is turned into the protocol's
 * artifacts. Everything here is a read — the protocol treats the data layer as
 * trusted for availability only, so all of it is public and unauthenticated.
 *
 * Kept separate from `te.ts` on purpose: that router serves the browser's audit
 * panel and the legacy write paths, and its shapes are load-bearing for the UI.
 * Mixing the two would make it unclear which shape may change.
 */

import { capture } from '@snapshot-labs/snapshot-sentry';
import express from 'express';
import {
  eligibilityPublicKey,
  GegAttestationError,
  mintAttestation
} from './helpers/gegAttestation';
import {
  composeElectionConfig,
  GegConfigError,
  parseCommitteeSnapshot
} from './helpers/gegConfig';
import log from './helpers/log';
import db from './helpers/mysql';
import { sendError } from './helpers/utils';

const router = express.Router();

/** How many proposals one `list` response may name. */
const LIST_LIMIT = 500;

function parseJsonField<T>(value: unknown, fallback: T): T {
  if (value === null || value === undefined) return fallback;
  if (typeof value === 'object') return value as T;
  if (typeof value === 'string') {
    try {
      return JSON.parse(value) as T;
    } catch {
      return fallback;
    }
  }
  return fallback;
}

async function loadProposal(proposalId: string): Promise<any | null> {
  const rows = await (db as any).queryAsync(
    `SELECT id, privacy, type, choices, start, end, te_mpk, te_committee_pks,
            te_geg_config, te_aggregate, te_dkg_status
       FROM proposals WHERE id = ? LIMIT 1`,
    [proposalId]
  );
  return rows[0] || null;
}

/**
 * The published eligibility key.
 *
 * The sequencer reads this at proposal creation and freezes the answer into the
 * proposal's config, which keeps the private key here as the single source of
 * truth rather than configuring the public half in two places.
 */
router.get('/te_eligibility_key', async (req, res) => {
  try {
    return res.json({ eligibilityKey: await eligibilityPublicKey() });
  } catch (err: any) {
    log.error(`[geg] eligibility key unavailable: ${err?.message || err}`);
    if (err instanceof GegAttestationError) {
      return sendError(res, 'eligibility_key_not_configured', 503);
    }
    capture(err);
    return sendError(res, 'server_error', 500);
  }
});

/**
 * Proposals the coordinator could still act on.
 *
 * Deliberately not the full history. The coordinator polls this on an interval
 * and then reads each entry, so returning every private proposal ever created
 * would make each tick cost O(history). It only ever acts on proposals awaiting
 * key generation or awaiting a tally, which is exactly what this filter keeps.
 *
 * The trade-off is that an auditor cannot enumerate history through here and must
 * be given proposal ids. The per-proposal reads remain complete and public.
 */
router.get('/te_geg_elections', async (req, res) => {
  try {
    const rows = await (db as any).queryAsync(
      `SELECT id FROM proposals
        WHERE privacy = 'shutter-elgamal'
          AND te_geg_config IS NOT NULL
          AND (te_dkg_status IS NULL OR te_dkg_status = '')
          AND (scores_state IS NULL OR scores_state != 'final')
        ORDER BY start ASC
        LIMIT ?`,
      [LIST_LIMIT]
    );
    return res.json({ electionIds: (rows as any[]).map(r => r.id) });
  } catch (err: any) {
    capture(err);
    return sendError(res, 'server_error', 500);
  }
});

/**
 * One election: its config plus the facts the protocol derives state from.
 *
 * `cancelled` is always false — Snapshot has no proposal cancellation, and
 * deletion removes the row entirely, which surfaces as a 404 instead.
 */
router.get('/proposal/:id/te_geg_election', async (req, res) => {
  const proposalId = req.params.id;
  try {
    const proposal = await loadProposal(proposalId);
    if (!proposal) return sendError(res, 'proposal_not_found', 404);
    if (proposal.privacy !== 'shutter-elgamal') {
      return sendError(res, 'proposal_not_private', 400);
    }

    let config;
    try {
      config = composeElectionConfig({
        proposalId,
        choices: parseJsonField<string[]>(proposal.choices, []),
        type: proposal.type,
        snapshot: parseCommitteeSnapshot(proposal.te_geg_config),
        currentEligibilityKey: await eligibilityPublicKey()
      });
    } catch (err: any) {
      if (err instanceof GegConfigError || err instanceof GegAttestationError) {
        log.error(`[geg] ${proposalId}: ${err.message}`);
        return sendError(res, err.message, 503);
      }
      throw err;
    }

    const committeePks = parseJsonField<string[] | null>(
      proposal.te_committee_pks,
      null
    );
    // A finalized key exists only once the committee reached its quorum, which is
    // the same moment te_mpk was written.
    const finalizedKey =
      proposal.te_mpk && committeePks?.length
        ? {
            pkElection: `0x${Buffer.from(proposal.te_mpk).toString('hex')}`,
            committeePKs: committeePks
          }
        : null;

    return res.json({
      config,
      cancelled: false,
      tallyStalled: false,
      finalizedKey
    });
  } catch (err: any) {
    log.error(`[geg] te_geg_election ${proposalId}: ${err?.message || err}`);
    capture(err);
    return sendError(res, 'server_error', 500);
  }
});

/**
 * Every stored ballot as a protocol ballot envelope, each carrying a freshly
 * minted eligibility credential.
 *
 * **Ordering.** The protocol requires a stable total order with monotonic
 * sequence numbers, because a ballot's admission is expressed *as* its sequence
 * number inside an artifact every keyper must produce byte-identically. Snapshot's
 * votes table has no monotonic column and a re-vote updates its row in place, so
 * the order is `(created, id)` and the sequence number is the row's index in it.
 * That is deterministic, and stable by the time it matters: keypers only read
 * ballots after voting has closed, when no row can change again.
 *
 * **Dust.** A voter with `0 < vp < 0.5` rounds to weight 0, which the protocol
 * rejects outright — and rejecting it here would abort the whole read rather than
 * skip one ballot. Such a ballot already contributes nothing to a tally (a
 * zero-weight ballot adds zero), so it is omitted. That keeps results identical to
 * the legacy path. The cost is that an omitted ballot appears in neither the
 * admitted set nor the exclusions, which again matches existing behaviour.
 */
router.get('/proposal/:id/te_geg_ballots', async (req, res) => {
  const proposalId = req.params.id;
  try {
    const proposal = await loadProposal(proposalId);
    if (!proposal) return sendError(res, 'proposal_not_found', 404);
    if (proposal.privacy !== 'shutter-elgamal') {
      return sendError(res, 'proposal_not_private', 400);
    }

    const start = Math.max(
      0,
      parseInt(String(req.query.start ?? '0'), 10) || 0
    );
    const rawCount = parseInt(String(req.query.count ?? '0'), 10);
    const countOnly = req.query.countOnly === '1';

    // cb != -3 excludes soft-deleted votes (CB.PENDING_DELETE in the sequencer).
    // Ordering must match the sequence-number derivation above exactly.
    const rows = await (db as any).queryAsync(
      `SELECT voter, vp, choice, created, id
         FROM votes
        WHERE proposal = ? AND cb != -3
        ORDER BY created ASC, id ASC`,
      [proposalId]
    );

    // Resolve the emitted set and its sequence numbers first, then slice. Doing
    // it in one pass would make `total` depend on where pagination stopped, and
    // would mint credentials for ballots the caller never asked for.
    const emitted: Array<{
      seq: number;
      row: any;
      weight: bigint;
      envelope: any;
    }> = [];
    for (const row of rows as any[]) {
      const weight = BigInt(Math.round(Number(row.vp)));
      if (weight < 1n) continue; // dust — contributes nothing, see above
      const envelope = parseJsonField<any>(row.choice, null);
      if (!envelope?.ciphertexts) {
        log.warn(`[geg] ${proposalId}: vote ${row.id} has no ballot envelope`);
        continue;
      }
      // Sequence numbers index this emitted list, so they stay dense — the
      // admitted set the keypers publish refers to these positions.
      emitted.push({ seq: emitted.length, row, weight, envelope });
    }

    if (countOnly) return res.json({ count: emitted.length });

    const page =
      rawCount > 0
        ? emitted.slice(start, start + rawCount)
        : emitted.slice(start);

    const ballots: any[] = [];
    for (const { row, weight, envelope } of page) {
      const nonce = BigInt(row.created);
      let signature: string;
      try {
        signature = await mintAttestation({
          electionId: proposalId,
          pseudonym: envelope.pseudonym,
          vk: envelope.vk,
          weight,
          nonce
        });
      } catch (err: any) {
        if (err instanceof GegAttestationError) {
          log.error(
            `[geg] ${proposalId}: cannot mint credential: ${err.message}`
          );
          return sendError(res, err.message, 503);
        }
        throw err;
      }

      ballots.push({
        electionId: proposalId,
        pseudonym: envelope.pseudonym,
        vk: envelope.vk,
        ciphertexts: envelope.ciphertexts,
        zkProof: envelope.zkProof,
        voterSignature: envelope.voterSignature,
        attestation: {
          scheme: 'ATTESTATION_V1',
          electionId: proposalId,
          pseudonym: envelope.pseudonym,
          vk: envelope.vk,
          weight: Number(weight),
          nonce: Number(nonce),
          signature
        }
      });
    }

    return res.json({ ballots, total: emitted.length });
  } catch (err: any) {
    log.error(`[geg] te_geg_ballots ${proposalId}: ${err?.message || err}`);
    capture(err);
    return sendError(res, 'server_error', 500);
  }
});

export default router;
