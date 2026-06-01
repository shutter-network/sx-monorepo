# Keyper deployment runbook

This document covers Phase 6 — operating the threshold-ElGamal keyper
committee that backs `privacy: 'shutter-elgamal'` proposals on
Snapshot.

> **Variant A, exact B=1, three keypers, threshold t=1.**
> Two honest keypers must agree before a tally can be opened. Any one
> keyper alone learns nothing.

## Components

| Component | Source | Role |
| --- | --- | --- |
| Hub | `apps/hub` | Holds the proposal row, the DKG submissions, and (after voting closes) the keypers' decryption shares. Express + MySQL. |
| Sequencer | `apps/sequencer` | Authenticated voter ingest; verifies every shutter-elgamal ballot at write time and runs the tally worker once `state === 'closed'`. |
| Keypers (×3) | `services/keypers` | Python service. Runs DKG against the hub at proposal-create time, signs partial decryptions at tally time. |
| UI | `apps/ui` | Voters build encrypted ballots locally with `@snapshot-labs/private-vote-sdk`. |

## docker-compose

`services/keypers/docker-compose.yml` ships a 3-keyper committee with
deterministic per-instance long-term keys for local development.
Spin it up alongside the hub:

```sh
cd services/keypers
docker compose up -d
```

The compose file binds:

- `keyper-1` on `:7001`
- `keyper-2` on `:7002`
- `keyper-3` on `:7003`

Each keyper needs `HUB_URL` in its environment to reach the hub's
`/api/proposal/:id/te_dkg` and `/api/proposal/:id/te_decryption_share`
endpoints. The hub also needs the keypers' addresses in its
`te_keyper_addresses` allow-list, configured per-proposal via Phase 7's
admin space settings (or directly in DB during dev).

## Per-proposal configuration

When a `shutter-elgamal` proposal is created, the hub writes:

| Column | Value |
| --- | --- |
| `te_config` | JSON: `{ numCandidates, budget: 1, mode: 'exact', variant: 'A' }` |
| `te_threshold_t` | `1` |
| `te_threshold_n` | `3` |
| `te_keyper_urls` | JSON array of three URLs (e.g. `["http://keyper-1:7001", ...]`) |
| `te_keyper_addresses` | JSON array of three EIP-191 signer addresses |

The UI surfaces the URLs as space-level settings (Phase 7). For local
dev, the test fixtures under `services/keypers/dev` populate these
columns directly with the docker-compose addresses.

## Lifecycle

1. **Proposal create.** Hub writes the row with `te_mpk = NULL`. The
   admin (or a watcher) POSTs `/api/proposal/:id/te_dkg` to each
   keyper, which runs DKG, produces an MPK + per-keyper share, and
   submits the result back to the hub. Once the hub sees `t+1` matching
   submissions, it stores the canonical `te_mpk` and `te_committee_pks`.
2. **Voting period.** Voters call `buildBallot` against `te_mpk`,
   encrypt their ballot, and submit through the existing snapshot.js
   sequencer flow. Each ballot is verified at ingest (`apps/sequencer/
   src/writer/vote.ts`) before persisting; rejected ballots return a
   structured error and are not written.
3. **Tally.** When the proposal transitions to `closed`, the
   sequencer's `runShutterElgamalTally` (`apps/sequencer/src/scores.ts`)
   builds the per-candidate homomorphic sum, persists `te_aggregate`,
   and POSTs `/decrypt/publish_on_chain` to each keyper. Each keyper
   pulls the aggregate, signs partial decryptions, and submits them to
   `/api/proposal/:id/te_decryption_share`. Once `t+1 = 2` shares are in,
   the sequencer Lagrange-combines, BSGS-recovers, and writes
   `proposal.scores`.
4. **Audit (any time after tally).** The hub serves
   `GET /api/proposal/:id/te_decryption_shares`. The UI's "Verify
   tally" button (Phase 8) re-runs `recoverTally` in the browser and
   compares to `proposal.scores`.

## Operational invariants

- **One DKG per proposal.** The hub's `te_dkg_submissions` table is
  keyed `(proposal_id, keyper_index)`; resubmitting the same keyper
  index is a no-op once a row exists.
- **Idempotent share writes.** `te_decryption_shares` uses
  `INSERT IGNORE` keyed on `(proposal_id, keyper_index, candidate)`.
- **Allow-list enforcement.** The hub rejects shares from any address
  not in `te_keyper_addresses`. Replacing keyper keys is a manual DB
  migration; do not hot-rotate a running proposal's committee.
- **No on-chain transport.** The `hub_client.py` shim stands in for
  the upstream Shutter on-chain coordination; everything happens over
  HTTP signed with EIP-191.

## Failure modes and recovery

| Symptom | Cause | Action |
| --- | --- | --- |
| `te_mpk` still `NULL` 5 min after proposal create | A keyper was offline during DKG, or hub auth rejected its address | Bring the keyper back up and POST `/api/proposal/:id/te_dkg` again. Do NOT change `te_keyper_addresses` mid-flight — that invalidates already-stored submissions. |
| Tally stuck after voting close | Fewer than `t+1` decryption shares | Inspect each keyper's logs, then trigger `/decrypt/publish_on_chain` manually. The sequencer runs idempotently. |
| Verify-tally button reports mismatch | Either a buggy keyper signed a bad share, or the sequencer aggregated a ballot twice | Re-run the tally worker from a clean DB snapshot. Compare per-candidate ciphertext sums against the keypers' stored aggregates. The DLEQ proofs themselves are public; an external auditor running the SDK can pinpoint the bad share. |

## Smoke test

For Phase 6 sign-off on a fresh checkout:

```sh
node scripts/parity-gate.mjs   # 23/23 must pass
cd services/keypers
docker compose up -d
# from another shell:
curl -s http://localhost:7001/healthz
curl -s http://localhost:7002/healthz
curl -s http://localhost:7003/healthz
```

A successful smoke test means: parity gate green; all three keypers
return `{"status":"ok"}` from their health endpoints.

## Production hardening (out of scope for v1)

- Replace the dev allow-list bootstrap with on-chain registry / DAO-
  governed list.
- Replace `() => true` WR-attestation verifier in
  `apps/sequencer/src/helpers/te.ts` with a real WR-Server signature
  check once the WR-Server lands.
- Move keyper key material out of docker-compose env vars into a real
  KMS / TEE.
- Add SLO monitoring on `te_decryption_shares` lag from voting-close.
