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

import {
  G2Point,
  initCurves,
  Transcript,
  verifyDecryptionShare
} from '@shutter-network/urban-verified-crypto';
import { capture } from '@snapshot-labs/snapshot-sentry';
import express from 'express';
import { parseJsonPreservingBigInts } from './helpers/bigIntJson';
import {
  eligibilityPublicKey,
  GegAttestationError,
  mintAttestation
} from './helpers/gegAttestation';
import {
  composeElectionConfig,
  deriveBallotParams,
  deriveMaxWeight,
  GegConfigError,
  parseCommitteeSnapshot
} from './helpers/gegConfig';
import {
  aggregateDigest,
  decryptionShareDigest,
  dkgResultDigest,
  GegDigestError,
  recoverDigestSigner,
  requestDigest,
  resultDigest
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
            te_geg_config, te_aggregate, te_dkg_status, te_tally_stalled
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
      // Drives the coordinator's state machine: a stalled election is one it
      // has given up driving, and it will not resume until this clears.
      tallyStalled: Boolean(proposal.te_tally_stalled),
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
    // The credential's weight is clamped to the ceiling this proposal's config
    // advertises, not passed through raw. The protocol excludes a ballot whose
    // attested weight exceeds maxWeight, so an unclamped whale would be dropped
    // from the tally entirely; counting it at the cap keeps it in, with the
    // weight the config permits. Derived from the same budget the config is
    // composed with, so the two can never disagree.
    let maxWeight: bigint;
    try {
      const snapshot = parseCommitteeSnapshot(proposal.te_geg_config);
      const { budget } = deriveBallotParams(
        parseJsonField<string[]>(proposal.choices, []),
        proposal.type,
        snapshot.weightedBudget
      );
      maxWeight = BigInt(deriveMaxWeight(budget));
    } catch (err: any) {
      if (err instanceof GegConfigError) {
        log.error(`[geg] ${proposalId}: ${err.message}`);
        return sendError(res, err.message, 500);
      }
      throw err;
    }
    for (const row of rows as any[]) {
      const rounded = BigInt(Math.round(Number(row.vp)));
      const weight = rounded > maxWeight ? maxWeight : rounded;
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
    for (const { seq, row, weight, envelope } of page) {
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

      // Storage metadata rides *alongside* the envelope, never inside it: the
      // envelope is the voter-signed artifact, so adding a field to it would
      // break the signature it carries. The committee reads `sequenceNumber`
      // from out here — it is the identifier the admitted set and the exclusion
      // list are expressed in, so a ballot emitted without one is a ballot the
      // aggregate cannot refer to.
      ballots.push({
        ballot: {
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
        },
        sequenceNumber: seq,
        // Snapshot's own receive time for the vote. The committee uses it to
        // check the voting window itself rather than trusting that ingest did.
        submittedAt: Number(row.created)
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
    const required = snapshot.thresholdT;

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

/**
 * The aggregate a quorum of the committee agreed on, or `null` while none has.
 *
 * Returns the string `'split'` for the case that must never be smoothed over:
 * two distinct artifacts each reaching the quorum. Picking either would make the
 * tally depend on row order, so callers surface it as a 409.
 *
 * Resolved from the signed submissions rather than `proposals.te_aggregate`,
 * which the superseded single-writer tally path also writes.
 */
async function canonicalAggregateFor(
  proposalId: string,
  snapshot: { thresholdT: number }
): Promise<any | null | 'split'> {
  const groups = await (db as any).queryAsync(
    `SELECT digest, COUNT(*) AS c, MIN(aggregate_json) AS aggregate_json
       FROM te_aggregate_submissions
      WHERE proposal_id = ?
      GROUP BY digest`,
    [proposalId]
  );
  const reached = groups.filter((g: any) => Number(g.c) >= snapshot.thresholdT);
  if (reached.length > 1) return 'split';
  if (reached.length === 0) return null;
  return parseJsonField<any>(reached[0].aggregate_json, null);
}

/**
 * Canonicalise an aggregate envelope for storage and comparison.
 *
 * The quorum counts submissions that agree *byte-for-byte*, so what is stored
 * has to be canonical: two keypers that derived the same tally must produce the
 * same string, and two that derived different tallies must not. Field order and
 * point capitalisation are normalised here for that reason — otherwise a
 * formatting difference reads as a disagreeing committee, which is the one
 * failure that looks exactly like a real split.
 *
 * The digest is what actually decides agreement (it is what the keypers signed);
 * this JSON is stored beside it so an auditor can see what each member claimed
 * when a quorum does not form.
 */
function canonicalAggregate(raw: any, electionId: string) {
  if (!raw || typeof raw !== 'object') {
    throw new GegDigestError('aggregate: expected an object');
  }
  const aggregates = (Array.isArray(raw.aggregates) ? raw.aggregates : []).map(
    (ct: any, i: number) => ({
      c1: canonicalPoint(ct?.c1, `aggregates[${i}].c1`, 96),
      c2: canonicalPoint(ct?.c2, `aggregates[${i}].c2`, 96)
    })
  );
  const admitted = (Array.isArray(raw.admitted) ? raw.admitted : []).map(
    (seq: any, i: number) => {
      if (!Number.isInteger(seq) || seq < 0) {
        throw new GegDigestError(`admitted[${i}]: expected a sequence number`);
      }
      return seq;
    }
  );
  const exclusions = (Array.isArray(raw.exclusions) ? raw.exclusions : []).map(
    (x: any, i: number) => {
      if (!Number.isInteger(x?.sequenceNumber) || x.sequenceNumber < 0) {
        throw new GegDigestError(
          `exclusions[${i}].sequenceNumber: expected a sequence number`
        );
      }
      if (typeof x?.reason !== 'string') {
        throw new GegDigestError(`exclusions[${i}].reason: expected a string`);
      }
      return { sequenceNumber: x.sequenceNumber, reason: x.reason };
    }
  );
  const totalAdmittedWeight = raw.totalAdmittedWeight ?? 0;

  return {
    electionId,
    aggregates,
    admitted,
    exclusions,
    totalAdmittedWeight
  };
}

/**
 * One keyper's aggregate, and the quorum rule that makes one of them canonical.
 *
 * Three behaviours here are the protocol's, not choices — they mirror its own
 * reference store, and diverging from any of them strands an election:
 *
 *   **422 before voting closes.** An aggregate over a still-open ballot set is
 *   meaningless, and accepting one would let a keyper fix the tally early.
 *
 *   **Mutable until the quorum forms.** Unlike the one-shot DKG result, the
 *   aggregate is a deterministic re-derivation, so a keyper that submitted a
 *   stale one must be able to replace it — the coordinator explicitly asks the
 *   committee to re-derive when their submissions disagree. Rejecting a change
 *   would freeze that disagreement permanently. After the quorum, the set is
 *   frozen and a change is a 409.
 *
 *   **A split quorum is a 409, not a winner.** If two distinct aggregates each
 *   reach the quorum, returning either one would make the tally depend on row
 *   order. That is a committee failure and is surfaced as one.
 */
router.post('/proposal/:id/te_aggregate', async (req, res) => {
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
      log.error(`[geg] ${proposalId}: ${err.message}`);
      return sendError(res, 'committee_not_configured', 503);
    }

    // 422 is what the protocol's client maps to its voting-window error; a 400
    // would be read as a malformed request and never retried.
    if (Math.floor(Date.now() / 1000) < Number(proposal.end)) {
      return sendError(res, 'aggregate submitted before voting_end', 422);
    }

    const { aggregate, keyperSig } = req.body || {};
    let canonical;
    try {
      canonical = canonicalAggregate(aggregate, proposalId);
    } catch (err: any) {
      return sendError(res, err?.message || 'bad_request', 400);
    }
    if (typeof keyperSig !== 'string') {
      return sendError(res, 'keyperSig: expected a string', 400);
    }

    let digest: Buffer;
    try {
      digest = aggregateDigest({
        electionId: proposalId,
        aggregates: canonical.aggregates,
        admitted: canonical.admitted,
        exclusions: canonical.exclusions,
        totalAdmittedWeight: canonical.totalAdmittedWeight
      });
    } catch (err: any) {
      return sendError(res, err?.message || 'bad_request', 400);
    }

    const signer = recoverDigestSigner(digest, keyperSig);
    const index = signer
      ? snapshot.keypers.findIndex(
          k => k.address.toLowerCase() === signer.toLowerCase()
        )
      : -1;
    if (index === -1) {
      log.warn(
        `[geg] ${proposalId}: aggregate from non-member ${signer ?? 'unrecoverable'}`
      );
      return sendError(res, 'not_a_registered_keyper', 403);
    }
    const keyperIndex = index + 1; // committee indices are 1-based
    const digestHex = `0x${digest.toString('hex')}`;
    const aggregateJson = JSON.stringify(canonical);

    const existing = await (db as any).queryAsync(
      'SELECT digest FROM te_aggregate_submissions WHERE proposal_id = ? AND keyper_index = ? LIMIT 1',
      [proposalId, keyperIndex]
    );
    if (existing[0]?.digest === digestHex) {
      return res.status(204).end(); // idempotent resend of this keyper's own row
    }
    if (existing[0] && proposal.te_aggregate) {
      log.warn(
        `[geg] ${proposalId}: keyper ${keyperIndex} changed its aggregate after the quorum`
      );
      return sendError(
        res,
        'aggregate already finalized (quorum reached)',
        409
      );
    }

    await (db as any).queryAsync(
      `INSERT INTO te_aggregate_submissions
         (proposal_id, keyper_index, keyper_address, aggregate_json, digest, signature, posted_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         aggregate_json = VALUES(aggregate_json),
         digest = VALUES(digest),
         signature = VALUES(signature),
         posted_at = VALUES(posted_at)`,
      [
        proposalId,
        keyperIndex,
        signer,
        aggregateJson,
        digestHex,
        keyperSig,
        Math.floor(Date.now() / 1000)
      ]
    );

    const groups = await (db as any).queryAsync(
      'SELECT digest, COUNT(*) AS c FROM te_aggregate_submissions WHERE proposal_id = ? GROUP BY digest',
      [proposalId]
    );
    const required = snapshot.thresholdT;
    const reached = groups.filter((g: any) => Number(g.c) >= required);

    if (reached.length > 1) {
      log.error(
        `[geg] ${proposalId}: ${reached.length} distinct aggregates each reached the quorum of ${required}`
      );
      return sendError(res, 'aggregate: split quorum', 409);
    }

    if (reached.length === 1) {
      // `WHERE te_aggregate IS NULL` makes promotion atomic: concurrent
      // submissions race harmlessly because only the first UPDATE matches.
      const winner = await (db as any).queryAsync(
        'SELECT aggregate_json FROM te_aggregate_submissions WHERE proposal_id = ? AND digest = ? LIMIT 1',
        [proposalId, reached[0].digest]
      );
      await (db as any).queryAsync(
        'UPDATE proposals SET te_aggregate = ? WHERE id = ? AND te_aggregate IS NULL',
        [winner[0].aggregate_json, proposalId]
      );
      log.info(
        `[geg] ${proposalId}: aggregate canonical at ${reached[0].c}/${required} matching submissions`
      );
    } else {
      const mine = groups.find((g: any) => g.digest === digestHex);
      log.info(
        `[geg] ${proposalId}: aggregate submission ${mine?.c ?? 1}/${required} from keyper ${keyperIndex}`
      );
    }

    return res.status(204).end();
  } catch (err: any) {
    log.error(`[geg] te_aggregate ${proposalId}: ${err?.message || err}`);
    capture(err);
    return sendError(res, 'server_error', 500);
  }
});

/**
 * The canonical aggregate, or null while the committee has not agreed on one.
 *
 * Resolved from the submissions rather than read back from
 * `proposals.te_aggregate`. That column is also written by the superseded
 * single-writer tally path, whose artifact is a bare ciphertext sum with no
 * admitted set, no exclusions and no total weight — serving it here would hand
 * the committee something that only looks like an aggregate, and the protocol
 * would either fail to decode it or, worse, act on a tally nobody signed.
 * Resolving from the signed submissions cannot be polluted that way.
 */
router.get('/proposal/:id/te_geg_aggregate', async (req, res) => {
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
      log.error(`[geg] ${proposalId}: ${err.message}`);
      return sendError(res, 'committee_not_configured', 503);
    }

    const canonical = await canonicalAggregateFor(proposalId, snapshot);

    // Two artifacts at quorum is a committee failure, not a tie to break:
    // returning either would make the tally depend on row order.
    if (canonical === 'split') {
      log.error(
        `[geg] ${proposalId}: distinct aggregates each reached the quorum`
      );
      return sendError(res, 'aggregate: split quorum', 409);
    }

    return res.json({ aggregate: canonical });
  } catch (err: any) {
    log.error(`[geg] te_geg_aggregate ${proposalId}: ${err?.message || err}`);
    capture(err);
    return sendError(res, 'server_error', 500);
  }
});

const DECRYPT_TRANSCRIPT_LABEL = 'SHUTTER-VOTE-DECRYPT-v1';

let curvesReady: Promise<void> | null = null;
function ensureCurves(): Promise<void> {
  if (!curvesReady) curvesReady = initCurves();
  return curvesReady;
}

/**
 * Check a keyper's DLEQ proofs before storing its shares.
 *
 * Storage is append-only, so an unverified share would be permanent: the first
 * one recorded is the one every later recovery uses. A bad proof caught here is
 * a 400 the keyper can act on; the same proof stored and discovered later is an
 * election that cannot be tallied and cannot be corrected.
 *
 * This duplicates a check the committee also performs — deliberately. It is the
 * one place the hub can independently confirm that what it is about to keep
 * forever actually decrypts the aggregate it agreed on.
 */
async function verifyShareProofs(
  proposalId: string,
  keyperIndex: number,
  entries: Array<{ sigma: string; proof: string }>,
  aggregates: Array<{ c1: string; c2: string }>,
  committeePKs: string[]
): Promise<number | null> {
  await ensureCurves();
  const hex = (v: string) => Buffer.from(String(v).replace(/^0x/, ''), 'hex');
  const pkHex = committeePKs[keyperIndex - 1];
  if (!pkHex) return -1; // no published key for this member

  for (let candidate = 0; candidate < entries.length; candidate++) {
    let c1: G2Point | null = null;
    let c2: G2Point | null = null;
    let sigma: G2Point | null = null;
    let pk: G2Point | null = null;
    try {
      c1 = G2Point.fromBytes(hex(aggregates[candidate].c1));
      c2 = G2Point.fromBytes(hex(aggregates[candidate].c2));
      sigma = G2Point.fromBytes(hex(entries[candidate].sigma));
      pk = G2Point.fromBytes(hex(pkHex));

      const proof = hex(entries[candidate].proof);
      const transcript = new Transcript(DECRYPT_TRANSCRIPT_LABEL);
      transcript.append('electionId', hex(proposalId));
      const candidateBuf = Buffer.alloc(2);
      candidateBuf.writeUInt16BE(candidate, 0);
      transcript.append('candidate', candidateBuf);

      const ok = verifyDecryptionShare(
        { c1, c2 },
        {
          keyperIndex,
          sigma,
          proof: {
            e: BigInt(`0x${proof.subarray(0, 32).toString('hex')}`),
            z: BigInt(`0x${proof.subarray(32).toString('hex')}`)
          }
        },
        pk,
        transcript
      );
      if (!ok) return candidate;
    } catch {
      return candidate;
    } finally {
      c1?.destroyWasm();
      c2?.destroyWasm();
      sigma?.destroyWasm();
      pk?.destroyWasm();
    }
  }
  return null;
}

/**
 * One keyper's decryption shares — its partial decryption of every candidate.
 *
 * Ordering is the whole point of the two window checks. A share is a partial
 * decryption *of a specific ciphertext*, so it is meaningless until the
 * committee has agreed which ciphertext that is:
 *
 *   - before voting closes there is no final ballot set;
 *   - before a canonical aggregate exists there is no agreed sum to decrypt,
 *     and a share computed against a candidate aggregate that later loses the
 *     quorum would be silently wrong rather than visibly rejected.
 *
 * Both answer 422 — the protocol's voting-window error — because the condition
 * is temporary and the caller should retry, unlike a 400.
 *
 * Shares are append-only: unlike the aggregate, a share is not a re-derivable
 * artifact the committee converges on, and `INSERT IGNORE` semantics mean the
 * first one stored is permanent — so a second, different submission from the
 * same keyper is a 409 rather than an overwrite.
 *
 * The envelope is per keyper across all candidates; storage is per (keyper,
 * candidate), which is what the existing audit surface and the legacy verifier
 * read. The split happens here rather than in the translator because the
 * signature covers the whole entries list: only a party holding the complete
 * envelope can verify it.
 */
router.post('/proposal/:id/te_geg_decryption_share', async (req, res) => {
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
      log.error(`[geg] ${proposalId}: ${err.message}`);
      return sendError(res, 'committee_not_configured', 503);
    }

    if (Math.floor(Date.now() / 1000) < Number(proposal.end)) {
      return sendError(
        res,
        'decryption share submitted before voting_end',
        422
      );
    }

    const canonical = await canonicalAggregateFor(proposalId, snapshot);
    if (canonical === 'split') {
      return sendError(res, 'aggregate: split quorum', 409);
    }
    if (!canonical) {
      return sendError(
        res,
        'decryption share submitted before a canonical aggregate exists',
        422
      );
    }

    const { share, keyperSig } = req.body || {};
    if (typeof keyperSig !== 'string') {
      return sendError(res, 'keyperSig: expected a string', 400);
    }
    const entries = Array.isArray(share?.entries) ? share.entries : null;
    if (!entries || entries.length === 0) {
      return sendError(res, 'share.entries: expected a non-empty array', 400);
    }
    if (entries.length !== canonical.aggregates.length) {
      // A short entries list decodes to a shorter tuple and would silently
      // corrupt recovery for the candidates it omits.
      return sendError(
        res,
        `share.entries: expected ${canonical.aggregates.length} entries, got ${entries.length}`,
        400
      );
    }

    let digest: Buffer;
    try {
      digest = decryptionShareDigest({ electionId: proposalId, entries });
    } catch (err: any) {
      return sendError(res, err?.message || 'bad_request', 400);
    }

    const signer = recoverDigestSigner(digest, keyperSig);
    const index = signer
      ? snapshot.keypers.findIndex(
          k => k.address.toLowerCase() === signer.toLowerCase()
        )
      : -1;
    if (index === -1) {
      log.warn(
        `[geg] ${proposalId}: decryption share from non-member ${signer ?? 'unrecoverable'}`
      );
      return sendError(res, 'not_a_registered_keyper', 403);
    }
    const keyperIndex = index + 1;

    // The envelope names its own index; the signature decides. A mismatch means
    // a keyper is claiming someone else's slot in the committee.
    if (
      share.keyperIndex !== undefined &&
      Number(share.keyperIndex) !== keyperIndex
    ) {
      return sendError(
        res,
        `share keyperIndex ${share.keyperIndex} does not match signer ${keyperIndex}`,
        403
      );
    }

    const existing = await (db as any).queryAsync(
      'SELECT candidate, HEX(sigma) AS sigma_hex, HEX(proof_e) AS e_hex, HEX(proof_z) AS z_hex FROM te_decryption_shares WHERE proposal_id = ? AND keyper_index = ? ORDER BY candidate',
      [proposalId, keyperIndex]
    );
    if (existing.length > 0) {
      const same =
        existing.length === entries.length &&
        existing.every((row: any, i: number) => {
          const proof = String(entries[i].proof || '')
            .replace(/^0x/, '')
            .toLowerCase();
          return (
            row.sigma_hex.toLowerCase() ===
              String(entries[i].sigma || '')
                .replace(/^0x/, '')
                .toLowerCase() &&
            `${row.e_hex}${row.z_hex}`.toLowerCase() === proof
          );
        });
      if (same) return res.status(204).end(); // idempotent resend
      log.warn(
        `[geg] ${proposalId}: keyper ${keyperIndex} already submitted different shares`
      );
      return sendError(res, 'keyper already submitted different shares', 409);
    }

    const committeePKs = parseJsonField<string[]>(
      proposal.te_committee_pks,
      []
    );
    const badCandidate = await verifyShareProofs(
      proposalId,
      keyperIndex,
      entries,
      canonical.aggregates,
      committeePKs
    );
    if (badCandidate !== null) {
      log.error(
        `[geg] ${proposalId}: keyper ${keyperIndex} DLEQ invalid for candidate ${badCandidate}`
      );
      return sendError(res, 'invalid_dleq_proof', 400);
    }

    const now = Math.floor(Date.now() / 1000);
    for (let candidate = 0; candidate < entries.length; candidate++) {
      const sigma = String(entries[candidate].sigma || '').replace(/^0x/, '');
      const proof = String(entries[candidate].proof || '').replace(/^0x/, '');
      if (sigma.length !== 192 || proof.length !== 128) {
        return sendError(res, `entries[${candidate}]: malformed`, 400);
      }
      await (db as any).queryAsync(
        `INSERT IGNORE INTO te_decryption_shares
           (proposal_id, keyper_index, candidate, sigma, proof_e, proof_z, posted_at)
         VALUES (?, ?, ?, UNHEX(?), UNHEX(?), UNHEX(?), ?)`,
        [
          proposalId,
          keyperIndex,
          candidate,
          sigma,
          proof.slice(0, 64),
          proof.slice(64),
          now
        ]
      );
    }

    log.info(
      `[geg] ${proposalId}: decryption shares from keyper ${keyperIndex} (${entries.length} candidates)`
    );
    return res.status(204).end();
  } catch (err: any) {
    log.error(
      `[geg] te_geg_decryption_share ${proposalId}: ${err?.message || err}`
    );
    capture(err);
    return sendError(res, 'server_error', 500);
  }
});

/**
 * Every keyper's shares, grouped back into the per-keyper envelopes the port
 * defines. A keyper missing an entry for any candidate is omitted entirely: a
 * partial envelope decodes to a shorter tuple and would corrupt recovery rather
 * than fail it.
 */
router.get('/proposal/:id/te_geg_decryption_shares', async (req, res) => {
  const proposalId = req.params.id;
  try {
    const proposal = await loadProposal(proposalId);
    if (!proposal) return sendError(res, 'proposal_not_found', 404);
    if (proposal.privacy !== 'shutter-elgamal') {
      return sendError(res, 'proposal_not_private', 400);
    }

    const choices = parseJsonField<string[]>(proposal.choices, []);
    const rows = await (db as any).queryAsync(
      'SELECT keyper_index, candidate, HEX(sigma) AS sigma_hex, HEX(proof_e) AS e_hex, HEX(proof_z) AS z_hex FROM te_decryption_shares WHERE proposal_id = ? ORDER BY keyper_index, candidate',
      [proposalId]
    );

    const byKeyper = new Map<number, any[]>();
    for (const row of rows) {
      const list = byKeyper.get(row.keyper_index) ?? [];
      list[row.candidate] = {
        sigma: `0x${row.sigma_hex.toLowerCase()}`,
        proof: `0x${row.e_hex.toLowerCase()}${row.z_hex.toLowerCase()}`
      };
      byKeyper.set(row.keyper_index, list);
    }

    const shares = [...byKeyper.entries()]
      .filter(
        ([, entries]) =>
          entries.length === choices.length && entries.every(Boolean)
      )
      .sort((a, b) => a[0] - b[0])
      .map(([keyperIndex, entries]) => ({
        electionId: proposalId,
        keyperIndex,
        entries
      }));

    return res.json({ shares });
  } catch (err: any) {
    log.error(
      `[geg] te_geg_decryption_shares ${proposalId}: ${err?.message || err}`
    );
    capture(err);
    return sendError(res, 'server_error', 500);
  }
});

/**
 * The published tally, signed by the result publisher.
 *
 * Authorisation differs from every other write here: this one is not a
 * committee member but the single `resultPublisherKey` frozen into the config —
 * the coordinator that recovered the totals. Recovery itself is not re-done
 * here; what the hub guarantees is that the artifact it stores is the one that
 * key signed, over these exact numbers.
 *
 * The signature binds the totals (upstream `GEG-RESULT-v1`). An earlier form
 * signed only (operation, election), which meant one captured signature
 * authorised *any* totals for that proposal — so this route deliberately fails
 * closed on a digest mismatch rather than trusting the caller's identity alone.
 *
 * Write-once: a result is the terminal artifact of an election, and a second
 * one would mean two different published outcomes. Identical resends are a
 * no-op so a coordinator retry after a dropped response is not an error.
 */
router.post('/proposal/:id/te_result', async (req, res) => {
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
      log.error(`[geg] ${proposalId}: ${err.message}`);
      return sendError(res, 'committee_not_configured', 503);
    }

    // Re-read the body from the raw text: totals routinely exceed 2^53, and the
    // parsed copy express handed us has already rounded them.
    let body: any = req.body;
    if (typeof (req as any).rawBody === 'string') {
      try {
        body = parseJsonPreservingBigInts((req as any).rawBody);
      } catch {
        return sendError(res, 'malformed json', 400);
      }
    }

    const result = body?.result;
    const sig = body?.resultPublisherSig;
    if (typeof sig !== 'string') {
      return sendError(res, 'resultPublisherSig: expected a string', 400);
    }

    // The publisher signs the *operation*, with the artifact digest as its
    // payload — not the artifact digest on its own. Verifying the inner digest
    // alone recovers a valid-looking address that simply is not the publisher's,
    // so the failure reads as "signed by a stranger" rather than as a mismatch.
    let digest: Buffer;
    try {
      digest = requestDigest(
        'result',
        proposalId,
        resultDigest({
          electionId: proposalId,
          totals: result?.totals,
          keyperIndices: result?.keyperIndices,
          bsgsBound: result?.bsgsBound
        })
      );
    } catch (err: any) {
      return sendError(res, err?.message || 'bad_request', 400);
    }

    const signer = recoverDigestSigner(digest, sig);
    if (
      !signer ||
      signer.toLowerCase() !== snapshot.resultPublisherAddress.toLowerCase()
    ) {
      log.warn(
        `[geg] ${proposalId}: result from ${signer ?? 'unrecoverable'}, not the result publisher`
      );
      return sendError(res, 'not_the_result_publisher', 403);
    }

    const totalsJson = JSON.stringify(result.totals.map((t: any) => String(t)));
    const indicesJson = JSON.stringify(
      result.keyperIndices.map((k: any) => Number(k))
    );
    const bsgsBound = String(result.bsgsBound);

    const existing = await (db as any).queryAsync(
      'SELECT totals_json, keyper_indices, bsgs_bound FROM te_results WHERE proposal_id = ? LIMIT 1',
      [proposalId]
    );
    if (existing[0]) {
      const same =
        existing[0].totals_json === totalsJson &&
        existing[0].keyper_indices === indicesJson &&
        existing[0].bsgs_bound === bsgsBound;
      if (same) return res.status(204).end();
      log.warn(`[geg] ${proposalId}: a different result was already published`);
      return sendError(res, 'result already published', 409);
    }

    await (db as any).queryAsync(
      `INSERT INTO te_results
         (proposal_id, totals_json, keyper_indices, bsgs_bound, signature, posted_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        proposalId,
        totalsJson,
        indicesJson,
        bsgsBound,
        sig,
        Math.floor(Date.now() / 1000)
      ]
    );
    log.info(`[geg] ${proposalId}: result published, totals ${totalsJson}`);
    return res.status(204).end();
  } catch (err: any) {
    log.error(`[geg] te_result ${proposalId}: ${err?.message || err}`);
    capture(err);
    return sendError(res, 'server_error', 500);
  }
});

/**
 * The published tally, or null.
 *
 * Totals are emitted as JSON *numbers* because that is what the protocol's codec
 * decodes — but they are stored as strings, so anything above 2^53 is written
 * into the response text from the stored decimal rather than round-tripped
 * through a double.
 */
router.get('/proposal/:id/te_result', async (req, res) => {
  const proposalId = req.params.id;
  try {
    const proposal = await loadProposal(proposalId);
    if (!proposal) return sendError(res, 'proposal_not_found', 404);
    if (proposal.privacy !== 'shutter-elgamal') {
      return sendError(res, 'proposal_not_private', 400);
    }

    const rows = await (db as any).queryAsync(
      'SELECT totals_json, keyper_indices, bsgs_bound FROM te_results WHERE proposal_id = ? LIMIT 1',
      [proposalId]
    );
    if (!rows[0]) return res.json({ result: null });

    const totals: string[] = JSON.parse(rows[0].totals_json);
    const indices: number[] = JSON.parse(rows[0].keyper_indices);
    const payload =
      `{"result":{"electionId":"${proposalId}",` +
      `"totals":[${totals.join(',')}],` +
      `"keyperIndices":[${indices.join(',')}],` +
      `"bsgsBound":${rows[0].bsgs_bound}}}`;
    res.type('application/json').send(payload);
  } catch (err: any) {
    log.error(`[geg] te_result ${proposalId}: ${err?.message || err}`);
    capture(err);
    return sendError(res, 'server_error', 500);
  }
});

/**
 * Mark a tally stalled, or clear it — two different writes wearing one route.
 *
 * The authorisation is **direction-split**, and that split is the whole design:
 *
 *   - `stalled: true` may only be signed by the `resultPublisherKey` — the
 *     coordinator, the one party that knows it has exhausted its attempts;
 *   - `stalled: false` may only be signed by `TE_ADMIN_ADDRESS`.
 *
 * If the coordinator could clear a stall, a restart would clear it: its retry
 * budget lives in memory, so a fresh process sees a stalled election, tries
 * again, and stalls again — an election looping quietly forever instead of
 * waiting for a human. Requiring a different identity to resume makes "someone
 * looked at this" a precondition rather than a hope.
 *
 * Both directions sign the same operation wrapper the result write uses, with
 * the direction encoded in the op name (`tally_stall` / `tally_resume`) and an
 * empty payload — so a stall signature cannot be replayed as a resume.
 */
router.post('/proposal/:id/te_tally_stalled', async (req, res) => {
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
      log.error(`[geg] ${proposalId}: ${err.message}`);
      return sendError(res, 'committee_not_configured', 503);
    }

    const stalled = req.body?.stalled;
    const sig = req.body?.resultPublisherSig ?? req.body?.adminSig;
    if (typeof stalled !== 'boolean') {
      return sendError(res, 'stalled: expected a boolean', 400);
    }
    if (typeof sig !== 'string') {
      return sendError(res, 'signature: expected a string', 400);
    }

    const op = stalled ? 'tally_stall' : 'tally_resume';
    const expected = stalled
      ? snapshot.resultPublisherAddress
      : snapshot.adminAddress;

    let signer: string | null;
    try {
      signer = recoverDigestSigner(requestDigest(op, proposalId), sig);
    } catch (err: any) {
      return sendError(res, err?.message || 'bad_request', 400);
    }
    if (!signer || signer.toLowerCase() !== expected.toLowerCase()) {
      log.warn(
        `[geg] ${proposalId}: ${op} from ${signer ?? 'unrecoverable'}, expected ${expected}`
      );
      return sendError(
        res,
        stalled ? 'not_the_result_publisher' : 'not_the_admin',
        403
      );
    }

    await (db as any).queryAsync(
      'UPDATE proposals SET te_tally_stalled = ? WHERE id = ? LIMIT 1',
      [stalled ? 1 : 0, proposalId]
    );
    log.info(
      `[geg] ${proposalId}: tally ${stalled ? 'marked stalled' : 'resumed by admin'}`
    );
    return res.status(204).end();
  } catch (err: any) {
    log.error(`[geg] te_tally_stalled ${proposalId}: ${err?.message || err}`);
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
