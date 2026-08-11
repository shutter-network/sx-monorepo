/**
 * The translator's contract, exercised against a stubbed hub.
 *
 * What matters here is not that requests are forwarded — it is that the protocol's
 * client sees exactly the contract it expects. Its callers branch on status type,
 * so a status collapsed to 500 changes the coordinator's behaviour: it retries what
 * it should abandon and abandons what it should retry. These tests pin the id
 * translation, the status pass-through, and the honest 501s.
 */

import fetch from 'node-fetch';
import request from 'supertest';
import { buildApp } from '../src/app';

// ts-jest hoists this above the imports, so `fetch` is already the mock by the
// time the app module resolves it.
jest.mock('node-fetch', () => jest.fn());

const mockFetch = fetch as unknown as jest.Mock;

const BARE = '1111111111111111111111111111111111111111111111111111111111111111';
const PREFIXED = `0x${BARE}`;

function hubReplies(body: unknown, status = 200): void {
  mockFetch.mockResolvedValueOnce({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body
  });
}

function lastUrl(): string {
  return mockFetch.mock.calls[mockFetch.mock.calls.length - 1][0];
}

let app: ReturnType<typeof buildApp>;

beforeEach(() => {
  process.env.HUB_URL = 'http://hub.test';
  mockFetch.mockReset();
  app = buildApp();
});

describe('service basics', () => {
  it('reports health without touching the hub', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  // Tier zero says: this data layer guarantees availability, not integrity. That
  // is the honest description — it can withhold an artifact but never forge one,
  // because every artifact is independently verifiable.
  it('declares verifiability tier zero', async () => {
    const res = await request(app).get('/capability');
    expect(res.body).toEqual({ verifiabilityTier: 0 });
  });

  it('404s an unknown route with a usable message', async () => {
    const res = await request(app).get('/nope');
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/no route for GET \/nope/);
  });
});

describe('election id translation', () => {
  it('accepts the bare hex the protocol client sends and prefixes it for the hub', async () => {
    hubReplies({ config: {}, cancelled: false });
    await request(app).get(`/elections/${BARE}`);
    expect(lastUrl()).toBe(
      `http://hub.test/api/proposal/${PREFIXED}/te_geg_election`
    );
  });

  it('also accepts a 0x-prefixed id, for a hand-typed request', async () => {
    hubReplies({ config: {} });
    await request(app).get(`/elections/${PREFIXED}`);
    expect(lastUrl()).toContain(PREFIXED);
  });

  it('lowercases a mixed-case id so it matches the stored proposal', async () => {
    hubReplies({ config: {} });
    await request(app).get(`/elections/${BARE.toUpperCase()}`);
    expect(lastUrl()).toContain(PREFIXED);
  });

  // A malformed id must be a clean 400 here. Forwarding it would surface as a
  // confusing 404 from the hub, or — worse — match a different proposal.
  it.each([
    ['too short', 'abcd'],
    ['too long', `${BARE}00`],
    ['not hex', 'z'.repeat(64)],
    ['odd length', BARE.slice(1)]
  ])(
    'rejects an id that is %s, without calling the hub',
    async (_label, eid) => {
      const res = await request(app).get(`/elections/${eid}`);
      expect(res.status).toBe(400);
      expect(mockFetch).not.toHaveBeenCalled();
    }
  );

  it('converts hub ids back to bare hex when listing', async () => {
    hubReplies({ electionIds: [PREFIXED, `0x${'ab'.repeat(32)}`] });
    const res = await request(app).get('/elections');
    expect(res.body.electionIds).toEqual([BARE, 'ab'.repeat(32)]);
  });
});

describe('reads', () => {
  it('passes the election record through untouched', async () => {
    const record = {
      config: { electionId: PREFIXED, numCandidates: 2 },
      cancelled: false,
      tallyStalled: false,
      finalizedKey: null
    };
    hubReplies(record);
    const res = await request(app).get(`/elections/${BARE}`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual(record);
  });

  it('derives the finalized key from the same election read', async () => {
    hubReplies({
      finalizedKey: { pkElection: '0xaa', committeePKs: ['0xbb'] }
    });
    const res = await request(app).get(`/elections/${BARE}/dkg/finalized`);
    expect(res.body.finalizedKey).toEqual({
      pkElection: '0xaa',
      committeePKs: ['0xbb']
    });
  });

  it('reports a missing finalized key as null rather than omitting it', async () => {
    hubReplies({ finalizedKey: null });
    const res = await request(app).get(`/elections/${BARE}/dkg/finalized`);
    expect(res.body).toEqual({ finalizedKey: null });
  });

  it('asks the hub for a count only', async () => {
    hubReplies({ count: 7 });
    const res = await request(app).get(`/elections/${BARE}/ballots/count`);
    expect(lastUrl()).toContain('countOnly=1');
    expect(res.body).toEqual({ count: 7 });
  });

  it('forwards ballot pagination', async () => {
    hubReplies({ ballots: [] });
    await request(app).get(`/elections/${BARE}/ballots?start=10&count=5`);
    expect(lastUrl()).toContain('start=10');
    expect(lastUrl()).toContain('count=5');
  });

  it('omits pagination that carries no information', async () => {
    hubReplies({ ballots: [] });
    await request(app).get(`/elections/${BARE}/ballots?start=0&count=0`);
    expect(lastUrl()).toBe(
      `http://hub.test/api/proposal/${PREFIXED}/te_geg_ballots`
    );
  });

  it('returns ballots under the key the protocol client reads', async () => {
    hubReplies({ ballots: [{ electionId: PREFIXED }], total: 1 });
    const res = await request(app).get(`/elections/${BARE}/ballots`);
    expect(res.body).toEqual({ ballots: [{ electionId: PREFIXED }] });
  });
});

describe('status pass-through', () => {
  // The client maps each of these onto a distinct error type, and its callers
  // branch on the type. Remapping any of them changes coordinator behaviour.
  it.each([[404], [403], [409], [422], [400], [503]])(
    'preserves hub status %i',
    async status => {
      hubReplies({ error: 'nope' }, status);
      const res = await request(app).get(`/elections/${BARE}`);
      expect(res.status).toBe(status);
    }
  );

  it('surfaces an unreachable hub as 502, not 500', async () => {
    // 502 says "the dependency failed, retrying may help"; 500 would suggest a
    // bug in this service and invite the wrong response.
    mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));
    const res = await request(app).get(`/elections/${BARE}`);
    expect(res.status).toBe(502);
    expect(res.body.error).toMatch(/hub unreachable/);
  });

  it('reports a missing HUB_URL as a server fault', async () => {
    delete process.env.HUB_URL;
    const res = await request(buildApp()).get(`/elections/${BARE}`);
    expect(res.status).toBe(500);
  });
});

describe('unsupported writes', () => {
  // 501 rather than a plausible-looking success: these operations exist in the
  // protocol but have no Snapshot equivalent, and pretending otherwise would let
  // a caller believe it had registered an election or cast a ballot.
  it.each([
    ['/elections', 'sequencer'],
    [`/elections/${BARE}/cancel`, 'cancellation'],
    [`/elections/${BARE}/ballots`, 'sequencer']
  ])('answers 501 for POST %s, explaining why', async (path, reason) => {
    const res = await request(app).post(path).send({});
    expect(res.status).toBe(501);
    expect(res.body.error).toContain(reason);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it.each([
    `/elections/${BARE}/dkg`,
    `/elections/${BARE}/aggregate`,
    `/elections/${BARE}/shares`,
    `/elections/${BARE}/result`,
    `/elections/${BARE}/tally-stalled`
  ])('answers 501 for the not-yet-wired route %s', async path => {
    expect((await request(app).post(path).send({})).status).toBe(501);
  });
});
