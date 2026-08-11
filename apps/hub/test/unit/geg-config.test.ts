/**
 * The proposal → election-config mapping.
 *
 * The protocol refuses to decode a config whose fields are the wrong shape, and a
 * rejected config makes every read fail — so this suite pins the mapping against
 * the protocol's own full-election vector, which is the authoritative example of
 * the wire shape. Comparing key sets and value *types* against that file is what
 * catches the traps a hand-written expectation would miss: `duplicatePolicy` is an
 * enum value rather than a member name, `protocolVersion` is a string rather than
 * a number, and `selfSubmitFee` is a decimal string because fees exceed 2^53.
 *
 * It also emits a fixture that geg's own decoder validates out of band:
 *
 *   WRITE_GEG_CONFIG_FIXTURE=1 bun run test:unit
 *   python3 ../../scripts/geg/verify-wire-fixtures.py
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  composeElectionConfig,
  deriveBallotParams,
  GegConfigError,
  MAX_WEIGHT,
  parseCommitteeSnapshot,
  PROTOCOL_VERSION,
  TeCommitteeSnapshot
} from '../../src/helpers/gegConfig';

const VECTOR_PATH = join(
  __dirname,
  '../../../../packages/private-vote-sdk/tests/vectors-geg/flow/full_election_level1.json'
);
const referenceConfig = JSON.parse(readFileSync(VECTOR_PATH, 'utf8')).config;

const PROPOSAL_ID =
  '0x1111111111111111111111111111111111111111111111111111111111111111';
const ELIGIBILITY_KEY =
  '0x972a59075fca0729b40b2cea5bb9685afdd219e77407e13631664c53b847cdcad45ab174a073aaa4122ad813fa094485';

const snapshot: TeCommitteeSnapshot = {
  v: 1,
  keypers: [
    {
      address: '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
      url: 'https://k1'
    },
    {
      address: '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
      url: 'https://k2'
    },
    { address: '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB', url: 'https://k3' }
  ],
  thresholdT: 1,
  thresholdN: 3,
  eligibilityKey: ELIGIBILITY_KEY,
  resultPublisherAddress: '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
  adminAddress: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
  votingStart: 1_770_000_000,
  votingEnd: 1_770_086_400,
  weightedBudget: 100
};

function compose(
  overrides: Partial<Parameters<typeof composeElectionConfig>[0]> = {}
) {
  return composeElectionConfig({
    proposalId: PROPOSAL_ID,
    choices: ['Yes', 'No', 'Abstain'],
    type: 'single-choice',
    snapshot,
    ...overrides
  });
}

describe('deriveBallotParams', () => {
  it('gives a single-choice proposal a budget of 1', () => {
    expect(deriveBallotParams(['Yes', 'No'], 'single-choice', 100)).toEqual({
      numCandidates: 2,
      budget: 1,
      mode: 'exact',
      variant: 'A'
    });
  });

  it('gives a weighted proposal the configured budget', () => {
    // Weighted splits are integers summing to the budget (60 + 40 = 100), so the
    // budget is the denominator the tally later divides by.
    expect(deriveBallotParams(['Yes', 'No'], 'weighted', 100).budget).toBe(100);
    expect(deriveBallotParams(['Yes', 'No'], 'weighted', 1000).budget).toBe(
      1000
    );
  });

  it('treats every non-weighted type as single-choice', () => {
    for (const type of [
      'single-choice',
      'approval',
      'quadratic',
      null,
      undefined
    ]) {
      expect(deriveBallotParams(['a', 'b'], type, 100).budget).toBe(1);
    }
  });

  it('counts candidates from the choices', () => {
    expect(
      deriveBallotParams(['a', 'b', 'c', 'd'], 'single-choice', 1).numCandidates
    ).toBe(4);
  });

  it('rejects a proposal with no choices', () => {
    expect(() => deriveBallotParams([], 'single-choice', 1)).toThrow(
      GegConfigError
    );
  });
});

describe('parseCommitteeSnapshot', () => {
  it('accepts both a parsed object and the raw JSON string a driver may return', () => {
    expect(parseCommitteeSnapshot(snapshot)).toEqual(snapshot);
    expect(parseCommitteeSnapshot(JSON.stringify(snapshot))).toEqual(snapshot);
  });

  it.each([
    ['a missing snapshot', null],
    ['an empty snapshot', {}],
    ['unparseable JSON', '{not json'],
    ['an unknown version', { ...snapshot, v: 2 }],
    ['no keypers', { ...snapshot, keypers: [] }]
  ])('rejects %s', (_label, raw) => {
    expect(() => parseCommitteeSnapshot(raw)).toThrow(GegConfigError);
  });

  // n and the committee list disagreeing means the quorum rule would be checked
  // against the wrong denominator, so it is refused rather than reconciled.
  it('rejects a committee whose size disagrees with n', () => {
    expect(() =>
      parseCommitteeSnapshot({ ...snapshot, thresholdN: 5 })
    ).toThrow(/lists 3 keypers but n = 5/);
  });
});

describe('composeElectionConfig', () => {
  it('produces the full wire config', () => {
    expect(compose()).toEqual({
      electionId: PROPOSAL_ID,
      numCandidates: 3,
      budget: 1,
      mode: 'exact',
      variant: 'A',
      weighted: true,
      maxWeight: MAX_WEIGHT,
      duplicatePolicy: 'last-wins',
      votingStart: 1_770_000_000,
      votingEnd: 1_770_086_400,
      threshold: { t: 1, n: 3 },
      keypers: [
        {
          signingKey: '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed',
          url: 'https://k1'
        },
        {
          signingKey: '0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359',
          url: 'https://k2'
        },
        {
          signingKey: '0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb',
          url: 'https://k3'
        }
      ],
      eligibilityKey: ELIGIBILITY_KEY,
      resultPublisherKey: '0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb',
      gatewayKeys: [],
      adminKey: '0xd8da6bf26964af9d7eed9e03e53415d37aa96045',
      protocolVersion: PROTOCOL_VERSION,
      selfSubmitFee: '0'
    });
  });

  // The mapping is only correct if it matches what the protocol actually emits.
  // Its own vector is the reference; a missing or extra key here is a decode
  // failure at runtime, which would take down every read.
  it('has exactly the key set of the protocol reference config', () => {
    expect(Object.keys(compose()).sort()).toEqual(
      Object.keys(referenceConfig).sort()
    );
  });

  it('matches the reference config field-for-field on type', () => {
    const got = compose() as unknown as Record<string, unknown>;
    for (const [key, reference] of Object.entries(referenceConfig)) {
      const mine = got[key];
      if (Array.isArray(reference)) {
        expect(Array.isArray(mine)).toBe(true);
      } else {
        expect({ key, type: typeof mine }).toEqual({
          key,
          type: typeof reference
        });
      }
    }
  });

  it.each([
    ['duplicatePolicy', 'last-wins'],
    ['protocolVersion', 'SHUTTER-VOTE-v1'],
    ['selfSubmitFee', '0'],
    ['mode', 'exact'],
    ['variant', 'A']
  ])('emits %s as the literal the protocol expects', (key, expected) => {
    // Pinned individually because each is a value a plausible refactor would
    // "tidy" into a member name or a number, and each such change makes every
    // read fail to decode rather than fail visibly here.
    expect((compose() as any)[key]).toBe(expected);
    if (key in referenceConfig) {
      expect(typeof (compose() as any)[key]).toBe(
        typeof (referenceConfig as any)[key]
      );
    }
  });

  it('lowercases the address-derived keys so digests are reproducible', () => {
    const config = compose();
    for (const value of [
      config.adminKey,
      config.resultPublisherKey,
      config.eligibilityKey,
      ...config.keypers.map(k => k.signingKey)
    ]) {
      expect(value).toBe(value.toLowerCase());
    }
  });

  it('carries the committee through in order', () => {
    expect(compose().keypers.map(k => k.url)).toEqual([
      'https://k1',
      'https://k2',
      'https://k3'
    ]);
  });

  it('leaves gatewayKeys empty, so ballot writes are not gated here', () => {
    // Ballots reach storage through the sequencer's own signed-message pipeline,
    // never through this API, so there is no gateway identity to authorise.
    expect(compose().gatewayKeys).toEqual([]);
  });

  it('offers a weight ceiling high enough never to bind', () => {
    // Snapshot voting power is uncapped; capping it would silently change
    // outcomes, so the ceiling exists only to satisfy the protocol's range check.
    expect(compose().maxWeight).toBe(Number.MAX_SAFE_INTEGER);
    expect(compose().weighted).toBe(true);
  });

  // A rotated eligibility key invalidates every credential on older proposals:
  // all ballots would be excluded and the tally would read as zeros with nothing
  // to explain it. Fail loudly instead.
  it('refuses to serve a config whose frozen eligibility key was rotated away', () => {
    expect(() =>
      compose({ currentEligibilityKey: `0x${'ab'.repeat(48)}` })
    ).toThrow(/was rotated/);
  });

  it('accepts a matching key regardless of case', () => {
    expect(() =>
      compose({ currentEligibilityKey: ELIGIBILITY_KEY.toUpperCase() })
    ).not.toThrow();
  });

  it('emits the fixture for the cross-language decode gate when asked', () => {
    const fixture = {
      description:
        'Election configs composed by the hub. geg dec_config must decode each one.',
      cases: [
        { name: 'single_choice_3_candidates', config: compose() },
        {
          name: 'weighted_budget_100',
          config: compose({ choices: ['A', 'B'], type: 'weighted' })
        },
        {
          name: 'single_keyper_t0',
          config: compose({
            snapshot: {
              ...snapshot,
              keypers: [snapshot.keypers[0]],
              thresholdT: 0,
              thresholdN: 1
            }
          })
        }
      ]
    };
    if (process.env.WRITE_GEG_CONFIG_FIXTURE) {
      writeFileSync(
        join(__dirname, '../fixtures/geg-configs.json'),
        `${JSON.stringify(fixture, null, 2)}\n`
      );
    }
    expect(fixture.cases).toHaveLength(3);
  });
});
