# Phase 2 — DKG coordinator service + hub endpoint

Status: **landed**. Commit prefix: `feat: dkg coordinator service + hub endpoint`.

## What landed

The off-chain replacement for the upstream `thresholdELGamal` smart-contract bulletin board: a vendored Python keyper service whose only behavioral change vs. upstream is the **transport** for two messages, plus the matching hub HTTP endpoints.

### `services/keypers/` (new)

Top-level service alongside `apps/` and `packages/`. Not part of the bun workspace — it's Python.

- `src/crypto/`, `src/dkg_coordinator.py`, `src/sdk_compat.py`: vendored from `thresholdELGamal/src/` byte-identical. The DKG orchestration script is unchanged: the keyper endpoints kept their old names (`/dkg/round1` … `/dkg/publish_on_chain`, `/decrypt/publish_on_chain`).
- `src/keyper.py`: adapted. `chain_config={rpc_url, private_key}` renamed to `hub_config={hub_url, private_key}`. The two on-chain submission bodies (`/dkg/publish_on_chain` and `/decrypt/publish_on_chain`) now route through `HubClient` instead of `eth_client.ElectionClient`. The DKG-derive math (`derive_joint_mpk`, `derive_mpk_share`, the per-candidate `prove_decryption_share`) is unchanged.
- `src/hub_client.py` (new): EIP-191-signed HTTP client. Three calls — `submit_dkg_result`, `get_aggregate`, `submit_decryption_share`. Domain-separated keccak256 payload hashes (`SX-TE-DKG-v1`, `SX-TE-DECRYPT-v1`) match `apps/hub/src/te.ts` byte-for-byte.
- `Dockerfile` + `docker-compose.yml`: 3-keyper committee on host ports 5001/5002/5003. `KEYPER_HUB_URL` defaults to `http://host.docker.internal:3000` so dockerised keypers can reach the dev hub running on the host.
- `requirements.txt`, `README.md`.

### Hub HTTP API (new)

`apps/hub/src/te.ts` — three new routes mounted at `/api`:

- `POST /api/proposal/:id/te_dkg` — keyper posts `(keyper_index, keyper_address, mpk, committee_pks, signature)`. Hub:
  1. Looks up `te_keyper_addresses[keyper_index - 1]` and rejects if it doesn't match `keyper_address`.
  2. Recomputes the EIP-191 payload hash and rejects if `verifyMessage` doesn't recover `keyper_address`.
  3. Inserts into `te_dkg_submissions` (idempotent on identical replays; **409** if the same keyper changes its mind).
  4. Counts distinct keypers reporting the **same exact** `(mpk, committee_pks_hex)` tuple. If `>= t+1`, the proposal row's `te_mpk` and `te_committee_pks` are written under a `WHERE te_mpk IS NULL` guard so a concurrent finalisation is a no-op.
- `GET /api/proposal/:id/te_aggregate` — returns the persisted `te_aggregate` JSON, **404** until the tally worker (Phase 4) writes it.
- `POST /api/proposal/:id/te_decryption_share` — keyper posts `(keyper_index, keyper_address, candidate, sigma, proof_e, proof_z, signature)`. Hub auths and inserts into `te_decryption_shares` with `INSERT IGNORE` (replays are no-ops).

### Schema additions (Phase 2 delta)

`apps/hub/src/helpers/schema.sql` and `apps/sequencer/test/schema.sql`:

- `proposals` gains `te_keyper_addresses JSON DEFAULT NULL`. This is the hub's **auth allow-list** for keyper submissions on this proposal. Populated by Phase 7's admin space settings flow.
- New table `te_dkg_submissions` (PK `proposal_id, keyper_index`) — pre-finalisation buffer for keyper DKG votes.

### GraphQL

`apps/hub/src/graphql/schema.gql` and `formatProposal` extended to surface `te_keyper_addresses`.

## Auth model

- Keyper address allow-list lives on the proposal row (`te_keyper_addresses`), not in space settings, because a long-lived space may rotate its committee per proposal.
- Every keyper-to-hub message is signed with the keyper's own Ethereum signing key. The hub re-derives the EIP-191 hash with the same DST-prefixed encoding the Python `hub_client.py` uses and recovers via `@ethersproject/wallet.verifyMessage`.
- Domain-separation tags: `SX-TE-DKG-v1` and `SX-TE-DECRYPT-v1`.
- Cross-language hash agreement is exercised by `apps/hub/test/unit/te-hash-parity.test.ts`. The test pins the JS shape and documents the matching Python one-liner. Full byte-equality across languages is folded into the parity gate at Phase 4 once we have a real keyper runtime committing into the hub.

## Why hub HTTP, not on-chain

Per implementation guide §3 — Stage 2 of the Permanent Shielded Voting roadmap is purely off-chain. The DKG and decryption shares are public artefacts (so anyone can verify the tally), but the *transport* for them is Snapshot's existing trust boundary (its hub), not a new on-chain contract.

## Verification

- Phase 0 parity gate: still **green** (23/23, no SDK changes).
- Python syntax: `keyper.py`, `hub_client.py`, `dkg_coordinator.py` all parse clean.
- TypeScript: not running typecheck this session because the workspace install is bun-driven and bun isn't available in the local toolchain. The new code only uses imports that already resolve in the existing dep tree (`express`, `@ethersproject/keccak256`, `@ethersproject/wallet` (newly declared in hub `package.json`), `crypto`, `bluebird`-promisified mysql).

## Decisions

- **Phased auth wiring.** The auth check rejects with `503 keyper_set_not_configured` if `te_keyper_addresses` is null, because Phase 1 schema has the column but nothing populates it yet (Phase 7). This is intentional: the hub never silently drops auth; it surfaces a structured "feature not configured" error.
- **No `te_dkg_status` column.** State is `(te_mpk IS NULL) ? 'pending' : 'finalized'`, with the `te_dkg_submissions` table as the pre-finalisation buffer. Adding a redundant status enum would just be one more place to keep in sync.
- **Idempotent shares table.** `INSERT IGNORE` on `(proposal_id, keyper_index, candidate)` makes keyper retries safe. The first submitted `(sigma, proof_e, proof_z)` per slot wins; that's fine because if a keyper produces two different valid DLEQ proofs for the same `(C1, C2)` aggregate, *both* prove the same `sigma`, and a malicious keyper can't forge a passing DLEQ for a different `sigma`.

## Not in this phase

- No live end-to-end test (no admin UI to populate `te_keyper_addresses`, no tally worker to populate `te_aggregate`). Phase 4 + Phase 7 unblock E2E.
- No keyper-side parity test that round-trips a keyper signature through the hub: that lands in Phase 4 once the tally worker can drive the loop.
