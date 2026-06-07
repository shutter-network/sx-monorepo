# Running permanent private voting locally

Operational notes for bringing up and testing the permanent-private (threshold-ElGamal /
`shutter-elgamal`) voting stack.

There are two ways to run the backend:

- **Docker (recommended for adopters)** — one command brings up the whole backend (MySQL, hub,
  sequencer, the 3-keyper committee, and the auto-DKG coordinator). See
  [section 1](#1-quick-start-with-docker-recommended). Full operator guide:
  [docker/README.md](../../docker/README.md).
- **Native dev (manual)** — run each process directly on the host. Best for active development of
  an individual service with hot reload. See [section 2](#2-components--ports-native-dev) onward.

Either way, the UI is run on the host (it is not containerized — operators typically ship it as
static assets behind their own CDN).

The commands below assume a Linux or macOS shell (bash/zsh). Prerequisites for native dev:
[Bun](https://bun.sh), Python 3.11+, and a local MySQL 8 server.

---

## 1. Quick start with Docker (recommended)

From the monorepo root:

```sh
cp .env.example .env   # optional — sensible dev defaults are baked in
docker compose up --build
```

This builds two images (a shared bun image for the hub + sequencer, and a Python image shared by
the keypers + auto-DKG) and starts **7 containers**:

| Container | Host port | Role |
| --- | --- | --- |
| `mysql` | 3306 | `snapshot_hub` + `snapshot_sequencer` (schemas auto-loaded on first boot) |
| `hub` | 3000 | GraphQL + REST API; collects and finalizes DKG results |
| `sequencer` | 3001 | Vote ingestion + threshold tally worker |
| `keyper1` / `keyper2` / `keyper3` | 5001 / 5002 / 5003 | Threshold committee (Feldman VSS DKG + partial decryption) |
| `auto-dkg` | — | Watches for new private proposals and runs the DKG ceremony automatically |

The three keypers are intentionally separate processes: threshold-ElGamal (`t=1, n=3`) splits the
decryption key across them so no single party — and not the server — can decrypt alone. Running
them as three containers mirrors a real deployment where each keyper runs on independent
infrastructure.

### Run the UI against the Docker stack

```sh
cd apps/ui
bun install   # once
bun run dev   # http://localhost:8080, pointed at the dockerized hub/sequencer
```

### Health check / reset

```sh
curl http://localhost:3000/api        # hub
curl http://localhost:3001            # sequencer
curl http://localhost:5001/status     # keyper 1

docker compose ps                     # container states
docker compose logs -f auto-dkg       # watch DKG ceremonies
docker compose down                   # stop (keeps the mysql volume)
docker compose down -v                # stop and wipe all data
```

### Docker notes

- **Port already in use (`Bind for 0.0.0.0:3000 failed`)** — another process on the host already
  holds a default port. Override just the host side via env (the containers always talk to each
  other on the fixed internal ports), e.g. `HUB_PORT=3010`. Overridable:
  `HUB_PORT`, `SEQ_PORT`, `MYSQL_PORT`, `KEYPER1_PORT`, `KEYPER2_PORT`, `KEYPER3_PORT`.
- **Container-to-container MySQL** runs without TLS on the private compose network, so the hub and
  sequencer are started with `DB_SSL=false`. The MySQL helpers only attempt TLS when `DB_SSL` is
  not `false`, so host-run dev (TLS to a managed DB) is unchanged.
- **Keyper committee keys** are deterministic dev keys (`sha256("keyper-{id}")`). For a real
  deployment, set `KEYPER_PRIVATE_KEY_1/2/3` in `.env` to keys held by three independent operators
  and keep `KEYPER_PRIVATE_KEYS` (used by `auto-dkg` to derive the allow-list) in sync.
- **First boot only**: MySQL loads the schemas from `apps/hub/src/helpers/schema.sql` and
  `apps/sequencer/src/helpers/schema.sql` (mounted read-only). The `mysql-data` volume persists
  across `up`/`down`; use `down -v` to re-run schema init from scratch.

The end-to-end private vote flow (create proposal → auto-DKG → encrypted voting → automatic tally →
verify) is identical to the native path described in
[section 4](#4-end-to-end-private-vote-flow-fully-automatic).

---

## 2. Components & ports (native dev)

| Service | Port | Start dir | Command |
| --- | --- | --- | --- |
| MySQL 8 | 3306 | — | your local MySQL server |
| Hub (GraphQL + `/api`) | 3000 | `apps/hub` | `bun run dev` |
| Sequencer (EIP-712 ingest + auto-tally) | 3001 | `apps/sequencer` | `bun run dev` |
| Keypers ×3 + auto-DKG coordinator | 5001/5002/5003 | `services/keypers` | see below |
| UI (Vite dev server) | 8080 | `apps/ui` | `bun run dev` |

- Create two databases on your local MySQL server, `snapshot_hub` and `snapshot_sequencer`, and
  load their schemas from `apps/hub/src/helpers/schema.sql` and
  `apps/sequencer/src/helpers/schema.sql` respectively. Connect as a user that can create and write
  to them.
- The hub and sequencer `.env` point at MySQL via their `HUB_DATABASE_URL` / `SEQ_DATABASE_URL`
  connection strings. For a plaintext local server, either use `localhost` as the host or set
  `DB_SSL=false` to disable TLS.
- The keypers are Python (3.11+). Create a virtualenv and install
  `services/keypers/requirements.txt` into it, then run them from `services/keypers`.
- The UI dev server listens on `localhost:8080`.

---

## 3. Startup sequence (native dev)

Start in this order (each later service assumes the earlier ones are up). Hub/sequencer/UI are
long-running; the keypers run as a foreground coordinator. Use separate terminals.

### 1. MySQL

Start your local MySQL 8 server and confirm it is listening on 3306, e.g.:

```sh
mysqladmin -h 127.0.0.1 -u root ping
```

### 2. Hub (:3000)

```sh
cd apps/hub
bun run dev
# ready when: "Started on: http://localhost:3000" + "[spaces] total spaces N"
```

### 3. Sequencer (:3001)

```sh
cd apps/sequencer
bun run dev
# ready when: "Started on: http://localhost:3001" + "[te-scheduler] started (every 5000ms)"
```

### 4. Keypers + auto-DKG (:5001/2/3)

```sh
cd services/keypers
python -m venv .venv && source .venv/bin/activate   # once
pip install -r requirements.txt                     # once
# start the 3 keypers (each on its own port) and the auto-DKG coordinator,
# e.g. via your process manager of choice, then:
python src/keyper.py --id 1 --port 5001 &
python src/keyper.py --id 2 --port 5002 &
python src/keyper.py --id 3 --port 5003 &
KEYPER_URLS=http://localhost:5001,http://localhost:5002,http://localhost:5003 \
  HUB_DB_HOST=127.0.0.1 python src/auto_dkg.py
# ready when each keyper /status responds and auto-DKG prints "coordinator started"
```

### 5. UI (:8080)

```sh
cd apps/ui
bun run dev
# open http://localhost:8080/#/s-tn:e2e-live.eth
```

### Health check (all services)

```sh
for p in 3000 3001 8080 5001 5002 5003 3306; do
  if nc -z localhost "$p" 2>/dev/null; then echo "$p: UP"; else echo "$p: DOWN"; fi
done
```

---

## 4. End-to-end private vote flow (fully automatic)

The whole flow needs only MetaMask signatures from the user — DKG and tally are automatic. This is
the same whether the backend runs natively or in Docker.

1. Open `http://localhost:8080/#/s-tn:e2e-live.eth` with an admin/member wallet.
2. Create a proposal and toggle **Private voting** ON (threshold-ElGamal). Pick a short duration
   (e.g. 3 min). Sign in MetaMask.
3. **auto-DKG** polls the DB every 2s; when it sees `privacy='shutter-elgamal' AND te_mpk IS NULL`
   it runs the DKG and sets `te_mpk` (~a few seconds). No manual DKG step. Natively this is
   `services/keypers/src/auto_dkg.py`; in Docker it is the `auto-dkg` container running the same
   script.
4. Vote: the UI builds a per-voter encrypted ballot envelope (`buildTeBallotEnvelope` →
   private-vote-sdk BLST WASM) and signs the EIP-712 `encryptedVoteTypes` message. While voting is
   open, every ballot is stored encrypted; individual choices are never visible.
5. When the voting period ends, the sequencer **te-scheduler**
   (`apps/sequencer/src/helpers/teTallyScheduler.ts`, every 5s) finds the closed private proposal,
   triggers keypers to publish decryption shares, recovers the homomorphic tally, and sets
   `scores_state='final'`. No manual decrypt step.
6. The closed proposal page shows the **Permanent private tally** panel with a **Verify tally**
   button (audits decryption shares vs. published scores).

---

## 5. Integration state (verified working)

- **Propose privacy**: `apps/ui/src/networks/offchain/actions.ts` `propose()` + `updateProposal()`
  pass `privacy: privacy === 'none' ? '' : privacy` so `shutter-elgamal` is preserved through
  EIP-712 signing (previously collapsed to `''` → proposals were not actually private).
- **Vote envelope encoding**: `apps/ui/src/helpers/teBallot.ts` `toHex` uses `hexlify` from
  `@ethersproject/bytes` (the Node `Buffer` path crashed in the browser).
- **sx.js shutter-elgamal support**: `packages/sx.js` `encryptChoices` passes the pre-built ballot
  through for `shutter-elgamal`. The UI consumes the **built** package via a junction
  (`apps/ui/node_modules/@snapshot-labs/sx` → `packages/sx.js`), so any edit to
  `packages/sx.js/src/**` requires a rebuild + Vite restart (see Gotchas).
- **Verify panel**: `apps/ui/src/helpers/teVerify.ts` `verifyTally` guards `if (!aggregate)` with a
  clear message (was crashing on closed proposals with zero votes).
- **Vote-choice masking**: `apps/ui/src/components/ProposalVoteChoice.vue` shows "Encrypted choice"
  + lock for active private proposals; plaintext only after completion. (Correct as-is.)
- **Results messaging**: `apps/ui/src/components/ProposalResults.vue` explains ballots stay
  encrypted until the period ends and only combined totals are decrypted.
- **Voting power (weighted ballots)**: a voter with voting power `N` is counted `N` times with **no
  change to the ballot cryptography**. `apps/sequencer/src/helpers/te.ts` `aggregateBallots` scales
  each ballot's ciphertexts by `w = round(vp)` (`scalarMulCt`) before the homomorphic sum, and
  `runShutterElgamalTally` uses `upperBound = Σ vp` for the BSGS discrete-log search.
- **Trustless tally audit**: anyone can verify the published scores were produced from the real,
  valid ballots — not invented or stuffed:
  - Hub: `GET /proposal/:id/te_ballots` serves every encrypted ballot (`voter`, `vp`, envelope), and
    `GET /proposal/:id/te_decryption_shares` now also returns `te_config`.
  - UI: `apps/ui/src/helpers/teVerify.ts` `verifyBallots` re-derives each pseudonym, runs the SDK
    `verifyBallot` zero-knowledge check, re-accumulates the **vp-weighted** homomorphic aggregate,
    and confirms it matches the aggregate the keypers actually decrypted. The **Verify tally** panel
    (`TeVerifyTallyPanel.vue`) shows "N/M ballots passed their zero-knowledge proof and the
    recomputed aggregate matches the decrypted one".
- Verified e2e: 3 encrypted ballots (2 Approve, 1 Reject) → tally `[2,1]` → 6 decryption shares
  (3 keypers × 2 candidates), with no plaintext stored in `votes.choice`.
- Verified e2e (voting power + audit): 3 ballots with `vp=[3,1,1]` voting `[cand0, cand0, cand1]`
  → weighted tally `[4,1]`; all 3 ballots pass `verifyBallot`, the recomputed vp-weighted aggregate
  equals the decrypted one, a tampered proof is rejected, and an independent `recoverTally` returns
  `[4,1]`.

---

## 6. Gotchas / troubleshooting

- **"Encryption type not supported" at vote time** → the built `packages/sx.js/dist` is stale.
  Rebuild and restart Vite with forced dep re-optimization:
  ```sh
  cd packages/sx.js
  bun run build            # tsc esnext + cjs
  cd ../../apps/ui
  bun run dev -- --force
  ```
  `node_modules` deps are not file-watched, so `--force` is required for the browser to pick up the
  rebuilt package. Editing `apps/ui/src/**` alone hot-reloads fine.
- **"Unknown column 'vp_value'"** (votes or leaderboard) → an older DB predates several columns. Run
  the matching `ALTER TABLE ... ADD COLUMN vp_value double NOT NULL DEFAULT '0' ...` (mirrored in
  `apps/hub/src/helpers/schema.sql`). The Docker stack loads the current schema automatically.
- **UI shows "non-premium network, cannot create proposals"** → hub derives `turbo` from
  `turbo_expiration > now` (not the `turbo` column). The seed sets `turbo_expiration = now + 10y`.
  Verify with GraphQL `{ space(id:"...") { turbo } }` → `true`.
- **Old proposals stay non-private forever** — privacy is fixed at creation. After any propose-path
  fix you must create a **new** proposal to test.
- **Non-private proposals hang on "Finalizing results"** — sequencer `scores.ts` calls external
  `score.snapshot.org`, unreachable locally. Private (`shutter-elgamal`) proposals tally locally and
  finalize fine. (Out of scope.)
- **Hub error decoding**: `sendError` always sets `error:"unauthorized"` literally; the real reason
  is in `error_description`. `server_error` = generic 500 — check hub stderr.
- **`[te-tally] aggregate failed: BLST not initialised`** → the homomorphic aggregation needs the
  BLST curve layer initialized. The ingest path inits it lazily, but the te-scheduler can tally in a
  process that never verified a ballot. Fixed by `await ensureCurvesInit()` before `aggregateBallots`
  in `apps/sequencer/src/scores.ts`.
- **`recoverTally: candidate X share from keyper Y failed verification`** → the proposal's committee
  keys were generated by an **earlier** keyper session (each DKG uses fresh randomness). To re-DKG an
  existing proposal against the live keypers: `DELETE FROM te_dkg_submissions WHERE proposal_id=?`
  (else the hub rejects with 409 `keyper_changed_submission`), set `proposals.te_mpk=NULL`, then run
  the DKG coordinator. Also `DELETE FROM te_decryption_shares WHERE proposal_id=?` before re-tallying
  so stale shares are replaced (the hub dedupes shares with `INSERT IGNORE`). Note the auto-DKG
  coordinator skips a proposal after 5 failures until keypers restart.

---

## 7. Keyper service and auto-DKG

The keyper committee and the auto-DKG coordinator both live in the monorepo at
[services/keypers/](../../services/keypers):

- `src/keyper.py` — a single committee member (run three, on ports 5001/5002/5003).
- `src/auto_dkg.py` — the DKG coordinator. It polls the hub database for new
  `privacy='shutter-elgamal'` proposals with no key yet and drives the committee through the DKG
  ceremony. All endpoints and DB connection details are read from the environment
  (`KEYPER_URLS`, `KEYPER_PRIVATE_KEYS`, `HUB_DB_HOST`, etc.), so the same script runs natively and
  in the `auto-dkg` container.
- `src/dkg_coordinator.py` — the orchestration primitives `auto_dkg.py` builds on.

The Docker stack wires three keyper containers plus the coordinator together via
[docker-compose.yml](../../docker-compose.yml); see [docker/README.md](../../docker/README.md) for
the one-command path.

To re-run DKG for an existing proposal (for example after restarting the committee), clear its prior
submissions as described in the last bullet of section 6, then let the coordinator pick it up again
(it polls continuously) or invoke the coordinator directly.
