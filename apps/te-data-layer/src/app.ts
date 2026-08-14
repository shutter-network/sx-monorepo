/**
 * The data-layer contract, served over Snapshot's hub.
 *
 * The keypers and their coordinator come from a separate codebase and speak one
 * fixed HTTP contract. This service implements that contract exactly — same paths,
 * same request and response bodies, same status semantics — so that side needs no
 * modification at all: it is pointed here by configuration and nothing else.
 *
 * Two properties are deliberate and load-bearing:
 *
 *   **Stateless and keyless.** No database handle, no signing key, no cache of
 *   record. Everything comes from the hub, which is the sole store. That is what
 *   makes it safe to run several replicas behind a load balancer, and it means a
 *   compromise here cannot forge an artifact — only withhold one.
 *
 *   **A translator, not an authority.** It maps shapes and forwards status. Where
 *   the protocol expects a write Snapshot has no equivalent for, it answers 501
 *   rather than inventing behaviour — see the four routes at the bottom.
 *
 * Route inventory and the reasoning behind each mapping live in
 * docs/private-voting/geg-integration-plan.md §4.
 */

import cors from 'cors';
import express, { Express, Request, Response } from 'express';
import { BadElectionId, toProposalId } from './eid';
import { HubError, hubGet, hubPost } from './hub';
import log from './log';

/** Writes the protocol defines but Snapshot has no equivalent for. */
const UNSUPPORTED: Array<{ path: string; reason: string }> = [
  {
    path: '/elections',
    reason:
      'elections are created as Snapshot proposals through the sequencer, not here'
  },
  {
    path: '/elections/:eid/cancel',
    reason: 'Snapshot has no proposal cancellation'
  },
  {
    path: '/elections/:eid/ballots',
    reason:
      'ballots are submitted as signed Snapshot votes through the sequencer, not here'
  }
];

/** Tally-artifact writes. Wired in a later phase; declared so the shape is visible. */
const PENDING_WRITES = [
  '/elections/:eid/aggregate',
  '/elections/:eid/shares',
  '/elections/:eid/result',
  '/elections/:eid/tally-stalled'
];

function fail(res: Response, status: number, message: string): void {
  res.status(status).json({ error: message, message });
}

/** The `:eid` path segment. Express types it as optional; a route match guarantees it. */
function electionIdParam(req: Request): string {
  const eid = req.params.eid;
  if (typeof eid !== 'string') {
    throw new BadElectionId('missing election id');
  }
  return eid;
}

/**
 * Run a handler, turning the two expected failure kinds into their statuses.
 *
 * A bad election id is the caller's error (400); a hub failure carries the status
 * the hub chose. Anything else is a genuine bug here and becomes a 500 — never
 * silently a 404, which would read to the coordinator as "this election does not
 * exist" and make it give up on a healthy proposal.
 */
function handle(
  fn: (req: Request, res: Response) => Promise<void>
): (req: Request, res: Response) => void {
  return (req, res) => {
    fn(req, res).catch(err => {
      if (err instanceof BadElectionId) return fail(res, 400, err.message);
      if (err instanceof HubError) return fail(res, err.status, err.message);
      log.error(`[te-dl] ${req.method} ${req.path}: ${err?.message || err}`);
      return fail(res, 500, 'internal error');
    });
  };
}

export function buildApp(): Express {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '20mb' }));
  // Reads are public by design: the protocol treats its data layer as trusted for
  // availability only, and every artifact it serves is independently verifiable.
  app.use(cors({ maxAge: 86400 }));

  app.get('/health', (req, res) => {
    res.json({ ok: true, uptimeS: Math.round(process.uptime()) });
  });

  /**
   * Verifiability tier. Zero means the data layer offers availability only — it
   * can withhold or reorder, but every artifact is self-verifying, so it cannot
   * forge one. That is an accurate description of a Snapshot-backed deployment.
   */
  app.get('/capability', (req, res) => {
    res.json({ verifiabilityTier: 0 });
  });

  app.get(
    '/elections',
    handle(async (req, res) => {
      const { electionIds } = await hubGet<{ electionIds: string[] }>(
        '/api/te_geg_elections'
      );
      // Ids pass through unchanged, and the reason is worth stating because the
      // contract is asymmetric: *path segments* carry bare hex, but every byte
      // field in a JSON body is `0x`-prefixed. Stripping the prefix here — the
      // obvious-looking move, given the paths — makes the client reject the whole
      // list with "missing '0x' prefix", and the coordinator then sees no elections
      // at all rather than an error it can attribute.
      res.json({ electionIds });
    })
  );

  app.get(
    '/elections/:eid',
    handle(async (req, res) => {
      const id = toProposalId(electionIdParam(req));
      res.json(
        await hubGet<Record<string, unknown>>(
          `/api/proposal/${id}/te_geg_election`
        )
      );
    })
  );

  app.post(
    '/elections/:eid/dkg',
    handle(async (req, res) => {
      const id = toProposalId(electionIdParam(req));
      // Forwarded verbatim. The keyper index is deliberately absent from this
      // payload — the hub recovers it from the signature, so a submission can only
      // ever count for whoever actually signed it.
      await hubPost(`/api/proposal/${id}/te_geg_dkg`, {
        pkElection: req.body?.pkElection,
        committeePKs: req.body?.committeePKs,
        keyperSig: req.body?.keyperSig
      });
      res.status(204).end();
    })
  );

  app.get(
    '/elections/:eid/dkg',
    handle(async (req, res) => {
      const id = toProposalId(electionIdParam(req));
      const { submissions } = await hubGet<{ submissions: unknown[] }>(
        `/api/proposal/${id}/te_geg_dkg`
      );
      res.json({ submissions });
    })
  );

  app.get(
    '/elections/:eid/dkg/finalized',
    handle(async (req, res) => {
      const id = toProposalId(electionIdParam(req));
      // Derived from the same read as the election itself: a finalized key exists
      // exactly when the committee reached its quorum.
      const { finalizedKey } = await hubGet<{ finalizedKey: unknown }>(
        `/api/proposal/${id}/te_geg_election`
      );
      res.json({ finalizedKey: finalizedKey ?? null });
    })
  );

  app.get(
    '/elections/:eid/ballots/count',
    handle(async (req, res) => {
      const id = toProposalId(electionIdParam(req));
      const { count } = await hubGet<{ count: number }>(
        `/api/proposal/${id}/te_geg_ballots?countOnly=1`
      );
      res.json({ count });
    })
  );

  app.get(
    '/elections/:eid/ballots',
    handle(async (req, res) => {
      const id = toProposalId(electionIdParam(req));
      const start = Number(req.query.start ?? 0);
      const count = Number(req.query.count ?? 0);
      const params = new URLSearchParams();
      if (Number.isFinite(start) && start > 0)
        params.set('start', String(start));
      if (Number.isFinite(count) && count > 0)
        params.set('count', String(count));
      const qs = params.toString();
      const { ballots } = await hubGet<{ ballots: unknown[] }>(
        `/api/proposal/${id}/te_geg_ballots${qs ? `?${qs}` : ''}`
      );
      res.json({ ballots });
    })
  );

  for (const { path, reason } of UNSUPPORTED) {
    app.post(path, (req, res) => fail(res, 501, reason));
  }

  for (const path of PENDING_WRITES) {
    app.post(path, (req, res) =>
      fail(res, 501, `${path} is not wired up in this deployment yet`)
    );
  }

  /**
   * Reads for artifacts that have no storage yet, answered as genuinely absent.
   *
   * These must **not** be 501. Lifecycle state is derived from the facts the data
   * layer reports, and "no result exists" is one of those facts — it is how the
   * coordinator distinguishes an election still awaiting its key from one already
   * complete. A 501 here is not a cautious answer, it is an unanswerable one: the
   * coordinator cannot derive state at all and abandons every election, including
   * the ones it should be driving.
   *
   * Reporting absence is also simply true. No aggregate or result artifact exists
   * for any election in this deployment yet.
   *
   * The legacy `proposals.te_aggregate` column is deliberately not surfaced here.
   * It holds a different artifact: a bare ciphertext sum with no admitted set, no
   * exclusions and no total weight. Dressing it up as the protocol's aggregate
   * would mean inventing the three fields it lacks, and those fields are exactly
   * what makes the artifact re-checkable.
   */
  app.get(
    '/elections/:eid/aggregate',
    handle(async (req, res) => {
      toProposalId(electionIdParam(req)); // validate the id even when the answer is fixed
      res.json({ aggregate: null });
    })
  );

  app.get(
    '/elections/:eid/shares',
    handle(async (req, res) => {
      toProposalId(electionIdParam(req));
      res.json({ shares: [] });
    })
  );

  app.get(
    '/elections/:eid/result',
    handle(async (req, res) => {
      toProposalId(electionIdParam(req));
      res.json({ result: null });
    })
  );

  app.use((req, res) =>
    fail(res, 404, `no route for ${req.method} ${req.path}`)
  );

  return app;
}
