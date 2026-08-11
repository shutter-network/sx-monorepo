import {
  buildCommitteeSnapshot,
  committeeColumns,
  parseKeypers,
  TeConfigError,
  TeEnv
} from '../../../src/helpers/teCommittee';

// A real 48-byte compressed G1 point, borrowed from the protocol's own
// attestation vectors so the shape check is exercised against a genuine key.
const ELIGIBILITY_KEY =
  '0x972a59075fca0729b40b2cea5bb9685afdd219e77407e13631664c53b847cdcad45ab174a073aaa4122ad813fa094485';

const K1 = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const K2 = '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359';
const K3 = '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB';
// Checksums above and here are the canonical EIP-55 forms, cross-checked
// against eth_utils.to_checksum_address rather than written by hand.
const ADMIN = '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb';

function env(overrides: Partial<TeEnv> = {}): TeEnv {
  return {
    keypers: `${K1}@https://k1.example.com,${K2}@https://k2.example.com,${K3}@https://k3.example.com`,
    thresholdT: '1',
    weightedBudget: '100',
    adminAddress: ADMIN,
    resultPublisherAddress: ADMIN,
    ...overrides
  };
}

const window = { votingStart: 1_770_000_000, votingEnd: 1_770_086_400 };

function build(overrides: Partial<TeEnv> = {}) {
  return buildCommitteeSnapshot({
    env: env(overrides),
    eligibilityKey: ELIGIBILITY_KEY,
    ...window
  });
}

describe('parseKeypers', () => {
  it('parses address@url pairs and strips trailing slashes', () => {
    expect(
      parseKeypers(`${K1}@https://k1.example.com/,${K2}@https://k2.example.com`)
    ).toEqual([
      { address: K1, url: 'https://k1.example.com' },
      { address: K2, url: 'https://k2.example.com' }
    ]);
  });

  it('treats an unset or blank value as no committee', () => {
    expect(parseKeypers(undefined)).toEqual([]);
    expect(parseKeypers('   ')).toEqual([]);
  });

  it('tolerates whitespace and trailing separators', () => {
    expect(parseKeypers(` ${K1}@https://k1.example.com , `)).toEqual([
      { address: K1, url: 'https://k1.example.com' }
    ]);
  });

  // EIP-55 is hand-rolled here (the sequencer has no @ethersproject/address),
  // so it is checked against the canonical vectors from the EIP itself. A wrong
  // checksum would silently fail to match the hub's write-authorisation lookup.
  it.each([
    ['0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed', K1],
    ['0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359', K2],
    ['0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb', K3],
    ['0xD1220A0CF47C7B9BE7A2E6BA89F429762E7B9ADB', ADMIN]
  ])('EIP-55 checksums %s', (input, expected) => {
    expect(parseKeypers(`${input}@https://k.example.com`)[0].address).toBe(
      expected
    );
  });

  it.each([
    ['no url separator', `${K1}`],
    ['malformed address', `0xnope@https://k.example.com`],
    ['short address', `0x1234@https://k.example.com`],
    ['empty url', `${K1}@`]
  ])('rejects %s', (_label, raw) => {
    expect(() => parseKeypers(raw)).toThrow(TeConfigError);
  });
});

describe('buildCommitteeSnapshot', () => {
  it('freezes the committee, roles, window and budget', () => {
    expect(build()).toEqual({
      v: 1,
      keypers: [
        { address: K1, url: 'https://k1.example.com' },
        { address: K2, url: 'https://k2.example.com' },
        { address: K3, url: 'https://k3.example.com' }
      ],
      thresholdT: 1,
      thresholdN: 3,
      eligibilityKey: ELIGIBILITY_KEY.toLowerCase(),
      resultPublisherAddress: ADMIN,
      adminAddress: ADMIN,
      votingStart: window.votingStart,
      votingEnd: window.votingEnd,
      weightedBudget: 100
    });
  });

  it('derives n from the committee rather than trusting a separate value', () => {
    const snapshot = build({
      keypers: `${K1}@https://k1.example.com,${K2}@https://k2.example.com`
    });
    expect(snapshot.thresholdN).toBe(2);
    expect(snapshot.keypers).toHaveLength(2);
  });

  it('defaults the threshold and the weighted budget', () => {
    const snapshot = build({
      thresholdT: undefined,
      weightedBudget: undefined
    });
    expect(snapshot.thresholdT).toBe(1);
    expect(snapshot.weightedBudget).toBe(100);
  });

  it('accepts a single-keyper committee at t = 0', () => {
    expect(
      build({ keypers: `${K1}@https://k1.example.com`, thresholdT: '0' })
    ).toMatchObject({ thresholdT: 0, thresholdN: 1 });
  });

  // Each of these produces a proposal whose key ceremony could never finish, so
  // they must fail at creation while the author can still see the error.
  it('rejects t >= n, which no quorum could ever satisfy', () => {
    expect(() => build({ thresholdT: '3' })).toThrow(/0 <= t < n/);
    expect(() => build({ thresholdT: '4' })).toThrow(/0 <= t < n/);
  });

  it('rejects a negative threshold', () => {
    expect(() => build({ thresholdT: '-1' })).toThrow(/0 <= t < n/);
  });

  it('rejects a duplicated keyper, which would inflate n past the real committee', () => {
    expect(() =>
      build({
        keypers: `${K1}@https://a.example.com,${K1.toLowerCase()}@https://b.example.com`
      })
    ).toThrow(/more than once/);
  });

  it('rejects an unconfigured committee', () => {
    expect(() => build({ keypers: undefined })).toThrow(/TE_KEYPERS/);
  });

  it.each([
    ['TE_ADMIN_ADDRESS', { adminAddress: undefined }],
    ['TE_RESULT_PUBLISHER_ADDRESS', { resultPublisherAddress: undefined }]
  ])('requires %s', (name, overrides) => {
    expect(() => build(overrides as Partial<TeEnv>)).toThrow(name);
  });

  it('rejects a non-address role key', () => {
    expect(() => build({ adminAddress: 'not-an-address' })).toThrow(
      /not an address/
    );
  });

  it('rejects a non-integer threshold', () => {
    expect(() => build({ thresholdT: '1.5' })).toThrow(/must be an integer/);
  });

  it('rejects a weighted budget below 1, which would make every split zero', () => {
    expect(() => build({ weightedBudget: '0' })).toThrow(/>= 1/);
  });

  it('rejects a malformed eligibility key', () => {
    expect(() =>
      buildCommitteeSnapshot({
        env: env(),
        eligibilityKey: '0xdeadbeef',
        ...window
      })
    ).toThrow(/compressed G1/);
  });

  it('rejects a window that ends before it starts', () => {
    expect(() =>
      buildCommitteeSnapshot({
        env: env(),
        eligibilityKey: ELIGIBILITY_KEY,
        votingStart: 200,
        votingEnd: 100
      })
    ).toThrow(/must be after/);
    expect(() =>
      buildCommitteeSnapshot({
        env: env(),
        eligibilityKey: ELIGIBILITY_KEY,
        votingStart: 100,
        votingEnd: 100
      })
    ).toThrow(/must be after/);
  });
});

describe('committeeColumns', () => {
  it('denormalises the committee for readers that already exist', () => {
    const snapshot = build();
    const columns = committeeColumns(snapshot);

    expect(columns.te_threshold_t).toBe(1);
    expect(columns.te_threshold_n).toBe(3);
    expect(JSON.parse(columns.te_keyper_urls)).toEqual([
      'https://k1.example.com',
      'https://k2.example.com',
      'https://k3.example.com'
    ]);
    // Checksummed, because the hub's authorisation path compares against
    // getAddress() output and a lowercase copy would never match.
    expect(JSON.parse(columns.te_keyper_addresses)).toEqual([K1, K2, K3]);
    // The snapshot is the authority; the columns above are copies of it.
    expect(JSON.parse(columns.te_geg_config)).toEqual(snapshot);
  });

  it('keeps the denormalised arrays aligned with the snapshot order', () => {
    const columns = committeeColumns(build());
    const addresses = JSON.parse(columns.te_keyper_addresses);
    const urls = JSON.parse(columns.te_keyper_urls);
    const snapshot = JSON.parse(columns.te_geg_config);
    snapshot.keypers.forEach((k: any, i: number) => {
      expect(addresses[i]).toBe(k.address);
      expect(urls[i]).toBe(k.url);
    });
  });
});
