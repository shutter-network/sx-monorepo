# Phase 4 — Tally worker for shutter-elgamal

## Scope

When a `privacy='shutter-elgamal'` proposal closes, replace the normal
score-API path with a homomorphic tally:

1. Re-aggregate all ballots in `votes` (vp-weighted, per candidate).
2. Persist the aggregate to `proposals.te_aggregate` (hub serves it via
   `GET /api/proposal/:id/te_aggregate`).
3. Trigger keypers (`POST {keyper_url}/decrypt/publish_on_chain`).
4. Read decryption shares from `te_decryption_shares` (DB shared with
   hub; hub is the writer via `POST /api/proposal/:id/te_decryption_share`,
   sequencer is the reader here).
5. Once every candidate has at least `t+1` valid shares, Lagrange-combine
   and BSGS-recover the integer per-candidate totals via the SDK's
   `recoverTally`.
6. Write `proposals.scores`, set `scores_state='final'`, and leave
   `scores_by_strategy` empty (per-voter strategy breakdown would leak
   individual ballots).

## Files changed

- `apps/sequencer/src/helpers/te.ts`:
  - Fix from earlier phase: `G2Point.fromCompressed` → `G2Point.fromBytes`
    (the SDK's actual API).
  - New: `envelopeCiphertexts`, `aggregateBallots`, `aggregateToJson`,
    `recoverTeTally`, `shareRowsToShares`, `triggerKeypers`,
    `decodeCommitteePks`.
- `apps/sequencer/src/scores.ts`:
  - `getProposal` now also parses `te_config`, `te_committee_pks`,
    `te_keyper_urls`, `te_aggregate` and hex-encodes `te_mpk`.
  - New branch `proposal.privacy === 'shutter-elgamal'` in
    `updateProposalAndVotes` short-circuiting to `runShutterElgamalTally`.
  - New `runShutterElgamalTally` function with the orchestration.
- `services/keypers/src/keyper.py`:
  - `/decrypt/publish_on_chain` now coerces `election_id` from a 0x-hex
    proposal id to the integer `sdk_compat.election_id_to_bytes32`
    expects. Without this, the Phase 2 keyper would 500 on every
    Snapshot proposal id.

## Wire-format anchors

The aggregate JSON shape (`TeAggregateJson`) is:
```
{
  "election_id": "0x<32 bytes hex>",
  "num_candidates": <int>,
  "ciphertexts": [{"c1": "0x<96 hex>", "c2": "0x<96 hex>"}, ...]
}
```
Both keyper.py (`publish_decryption_share`) and sequencer.scores
(`runShutterElgamalTally`) read/write this exact shape.

The decrypt transcript that `recoverTally` re-seeds matches the
keyper-side `make_onchain_decrypt_transcript`:

| step | tag         | bytes                           |
|------|-------------|---------------------------------|
| init | label       | `SHUTTER-VOTE-DECRYPT-v1`       |
| 1    | electionId  | 32 bytes (proposal id, raw)     |
| 2    | candidate   | u16 BE (candidate index)        |

## What this phase intentionally does NOT do

- No new unit test for the math: the SDK's parity gate already covers
  encrypt/share/combine/recover end-to-end (`tests/test_sdk_compat.py`).
  `runShutterElgamalTally` is wired so that all crypto bottlenecks go
  through the SDK; structural correctness is what we check here.
- No live-keyper integration test: requires MySQL + dockerised keypers
  + hub running, which is a Phase-6 deliverable.
- No retry/jitter/backoff on the keyper trigger: the scheduler that
  drives `updateProposalAndVotes` already provides retry granularity.
- `te_aggregate` is rewritten on every tick. This is fine — the
  homomorphic sum is deterministic given a fixed vote set, so writing
  the same JSON repeatedly costs an UPDATE and produces no observable
  drift.

## Known gaps

- `te_threshold_t` and `te_committee_pks` are read from `proposals` but
  not yet written there; Phase 7 (admin space settings) populates them
  as part of proposal creation.
- BSGS upper bound is the sum of voting power, rounded to integer. For
  spaces with very large vp totals (e.g. token-weighted with full ERC-20
  supply) this table could be expensive; v1 targets equal-weight or
  small-vp configurations.
- `Number(scores[j])` truncates to JS `number`. Safe for vp totals up
  to 2^53; well above any realistic Snapshot space, and the underlying
  bigint is preserved if a caller reads `te_aggregate` directly.

## Parity gate status

Green at commit time. No SDK changes in this phase.
