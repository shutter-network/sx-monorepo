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
import {
  dkgResultDigest,
  GegDigestError,
  recoverDigestSigner
} from './helpers/gegDigests';
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

/**
 * Normalise a compressed point to lowercase `0x` hex.
 *
 * The quorum rule counts *byte-identical* submissions, so the stored form has to
 * be canonical. Two keypers that agree on the key but disagree on capitalisation
 * would otherwise never reach quorum, and the failure would look like disagreement
 * rather than formatting.
 */
function canonicalPoint(value: unknown, label: string, size: number): string {
  const body =
    typeof value === 'string' &&
    (value.startsWith('0x') || value.startsWith('0X'))
      ? value.slice(2)
      : value;
  if (
    typeof body !== 'string' ||
    body.length !== size * 2 ||
    !/^[0-9a-fA-F]*$/.test(body)
  ) {
    throw new GegDigestError(`${label}: expected ${size} bytes of hex`);
  }
  return `0x${body.toLowerCase()}`;
}

/**
 * A keyper's DKG result.
 *
 * The keyper index is **recovered from the signature**, never taken from the
 * request. A claimed index would let any member submit on behalf of another and
 * occupy its slot in the quorum; recovering it means a submission can only ever
 * count for whoever actually signed it.
 *
 * The key is published once `t + 1` distinct members have submitted a
 * byte-identical `(pkElection, committeePKs)` pair. Honest keypers derive the same
 * pair from the same ceremony, so a divergent one simply never reaches quorum
 * rather than needing to be adjudicated.
 *
 * Submissions are recorded even after finalisation. Re-submitting the same values
 * is idempotent; submitting different ones is a conflict, because a keyper that
 * signed two different results for one election is evidence worth keeping rather
 * than a race to smooth over.
 */
router.post('/proposal/:id/te_geg_dkg', async (req, res) => {
  const proposalId = req.params.id;
  try {
    const proposal = await loadProposal(proposalId);
    if (!proposal) return sendError(res, 'proposal_not_found', 404);
    if (proposal.privacy !== 'shutter-elgamal') {
      return sendError(res, 'proposal_not_private', 400);
    }

    let snapshot;
    try {
      snapshot = parseCommitteeSnapshot(proposal.te_geg_config);
    } catch (err: any) {
      // No committee means there is nothing to authorise against. Refuse loudly
      // rather than storing an unverifiable submission.
      log.error(`[geg] ${proposalId}: ${err.message}`);
      return sendError(res, 'committee_not_configured', 503);
    }

    const { pkElection, committeePKs, keyperSig } = req.body || {};
    let pkCanon: string;
    let committeeCanon: string[];
    try {
      pkCanon = canonicalPoint(pkElection, 'pkElection', 96);
      if (!Array.isArray(committeePKs) || committeePKs.length === 0) {
        throw new GegDigestError('committeePKs: expected a non-empty array');
      }
      committeeCanon = committeePKs.map((pk, i) =>
        canonicalPoint(pk, `committeePKs[${i}]`, 96)
      );
    } catch (err: any) {
      return sendError(res, err?.message || 'bad_request', 400);
    }
    if (typeof keyperSig !== 'string') {
      return sendError(res, 'keyperSig: expected a string', 400);
    }
    if (committeeCanon.length !== snapshot.thresholdN) {
      return sendError(
        res,
        `committeePKs: expected ${snapshot.thresholdN} keys, got ${committeeCanon.length}`,
        400
      );
    }

    let signer: string | null;
    try {
      signer = recoverDigestSigner(
        dkgResultDigest({
          electionId: proposalId,
          pkElection: pkCanon,
          committeePKs: committeeCanon
        }),
        keyperSig
      );
    } catch (err: any) {
      return sendError(res, err?.message || 'bad_request', 400);
    }

    const index = signer
      ? snapshot.keypers.findIndex(
          k => k.address.toLowerCase() === signer!.toLowerCase()
        )
      : -1;
    if (index === -1) {
      log.warn(
        `[geg] ${proposalId}: DKG submission from non-member ${signer ?? 'unrecoverable'}`
      );
      // 403 is what the protocol's client maps to an authorisation error; a 401
      // here would be read as a transport problem and retried.
      return sendError(res, 'not_a_registered_keyper', 403);
    }
    const keyperIndex = index + 1; // committee indices are 1-based

    const committeeJson = JSON.stringify(committeeCanon);
    const existing = await (db as any).queryAsync(
      'SELECT mpk_hex, committee_pks_hex FROM te_dkg_submissions WHERE proposal_id = ? AND keyper_index = ? LIMIT 1',
      [proposalId, keyperIndex]
    );
    if (existing[0]) {
      if (
        existing[0].mpk_hex !== pkCanon ||
        existing[0].committee_pks_hex !== committeeJson
      ) {
        log.warn(
          `[geg] ${proposalId}: keyper ${keyperIndex} changed its DKG submission`
        );
        return sendError(res, 'keyper_changed_submission', 409);
      }
    } else {
      await (db as any).queryAsync(
        `INSERT INTO te_dkg_submissions
           (proposal_id, keyper_index, keyper_address, mpk_hex, committee_pks_hex, signature, posted_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          proposalId,
          keyperIndex,
          signer,
          pkCanon,
          committeeJson,
          keyperSig,
          Math.floor(Date.now() / 1000)
        ]
      );
    }

    const [{ c: matching }] = await (db as any).queryAsync(
      'SELECT COUNT(*) AS c FROM te_dkg_submissions WHERE proposal_id = ? AND mpk_hex = ? AND committee_pks_hex = ?',
      [proposalId, pkCanon, committeeJson]
    );
    const required = snapshot.thresholdT + 1;

    if (Number(matching) >= required) {
      // `WHERE te_mpk IS NULL` makes finalisation atomic: concurrent submissions
      // race harmlessly because only the first UPDATE matches.
      await (db as any).queryAsync(
        'UPDATE proposals SET te_mpk = UNHEX(?), te_committee_pks = ? WHERE id = ? AND te_mpk IS NULL',
        [pkCanon.slice(2), committeeJson, proposalId]
      );
      log.info(
        `[geg] ${proposalId}: DKG finalised at ${matching}/${required} matching submissions`
      );
    } else {
      log.info(
        `[geg] ${proposalId}: DKG submission ${matching}/${required} from keyper ${keyperIndex}`
      );
    }

    // 204: the protocol's port defines this write as returning nothing.
    return res.status(204).end();
  } catch (err: any) {
    log.error(`[geg] te_geg_dkg ${proposalId}: ${err?.message || err}`);
    capture(err);
    return sendError(res, 'server_error', 500);
  }
});

/** Every DKG submission recorded so far, for the auditor and the coordinator. */
router.get('/proposal/:id/te_geg_dkg', async (req, res) => {
  const proposalId = req.params.id;
  try {
    const proposal = await loadProposal(proposalId);
    if (!proposal) return sendError(res, 'proposal_not_found', 404);
    if (proposal.privacy !== 'shutter-elgamal') {
      return sendError(res, 'proposal_not_private', 400);
    }
    const rows = await (db as any).queryAsync(
      `SELECT keyper_index, mpk_hex, committee_pks_hex, signature
         FROM te_dkg_submissions WHERE proposal_id = ? ORDER BY keyper_index`,
      [proposalId]
    );
    return res.json({
      submissions: (rows as any[]).map(r => ({
        electionId: proposalId,
        pkElection: r.mpk_hex,
        committeePKs: parseJsonField<string[]>(r.committee_pks_hex, []),
        keyperSignature: r.signature
      }))
    });
  } catch (err: any) {
    log.error(`[geg] te_geg_dkg read ${proposalId}: ${err?.message || err}`);
    capture(err);
    return sendError(res, 'server_error', 500);
  }
});

export default router;
