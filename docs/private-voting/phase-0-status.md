# Phase 0 — Vendor private-vote SDK as workspace package

Status: **landed**. Commit prefix: `feat: vendor private-vote SDK as workspace package`.

## What landed

- `packages/private-vote-sdk/` — vendored from `Urban-Verified/shutter-voting-sdk` at upstream commit `17dcaf5`. Renamed to `@snapshot-labs/private-vote-sdk` (`private: true`), build script made cross-platform (`scripts/copy-wasm.mjs` replaces the Unix `cp`).
- `scripts/parity-gate.mjs` — TS↔Python parity gate (guide §8.5). Regenerates the SDK's deterministic fixture vectors, byte-syncs the four shared cross-impl fixtures into `Urban-Verified/thresholdELGamal/fixtures/`, runs `pytest tests/test_sdk_compat.py`, fails loudly on any drift.
- Root `package.json` — `bun run parity` shortcut.

## Verification

```text
$ node scripts/parity-gate.mjs
--- regenerate fixture vectors ---
  wrote encrypt/encrypt_m5_basic.json
  wrote dleq/dleq_basic.json
  wrote or/or_m2_B3.json
  wrote budget/budget_exact_B3.json
  wrote budget/budget_atMost_B3.json
  wrote schnorr/schnorr_basic.json
  wrote decrypt-share/share_basic.json
  wrote ballot/ballot_variantA_exact.json
  wrote ballot/ballot_variantA_atMost.json
  wrote ballot/ballot_tampered_ct.json
  wrote tally/tally_basic.json
--- sync shared fixtures ---
  ok  decrypt-share/thresholdElGamal_dkg_keyper_1.json
  ok  decrypt-share/thresholdElGamal_dkg_keyper_2.json
  ok  decrypt-share/thresholdElGamal_dkg_keyper_3.json
  ok  tally/thresholdElGamal_dkg_combined.json
--- pytest test_sdk_compat ---
collected 23 items
tests\test_sdk_compat.py .......................                         [100%]
============================= 23 passed in 0.32s ==============================
[parity-gate] OK — TS and Python agree on ballot bytes.
```

The four shared fixtures hash-match across both repos (`CE06FE11`, `69538BC6`, `C196D01E`, `DECB80AA`).

## Bootstrap (one-time per dev box)

```powershell
# clone alongside sx-monorepo
git clone https://github.com/Urban-Verified/thresholdELGamal.git ../thresholdELGamal
cd ../thresholdELGamal
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r src/requirements.txt pytest

# install the vendored SDK's deps
cd ../sx-monorepo/packages/private-vote-sdk
npm install --legacy-peer-deps
```

`THRESHOLD_ELGAMAL_PATH` overrides the default `../thresholdELGamal` location for CI runners that lay out the repos differently.

## E2E status for this phase

Phase 0 is a foundation phase — its "end-to-end test" per guide §7 is the parity gate, not a Playwright run. The full golden-path E2E (§8.3) starts being meaningful at Phase 5 once the UI vote modal exists.

## Open-decisions checklist (guide §6) settled in this phase

None. All §6 items are deferred to phases that need them.

## Notes for later phases

- The vendored package's `npm install` requires `--legacy-peer-deps` against npm 10. This is upstream peer-dep noise (`viem`/`buffer`), not a real conflict; switching the root install to bun (the monorepo's actual package manager) sidesteps it. Use bun once node is upgraded to ≥22.6 per `package.json#engines`.
- The Vite config change for serving `blst.wasm` (guide Phase 0 step 3) lands when `apps/ui` actually imports the SDK — Phase 5. Tracked as a TODO there, not here.
- `gen-vectors` only regenerates the 11 vectors it owns; the 4 `thresholdElGamal_dkg_*` fixtures were authored in the Python repo and committed into the SDK. The parity gate sources them from the SDK side and copies *into* the Python repo, so the Python repo is the dependent. If they're ever regenerated they should be regenerated in `thresholdELGamal` first, then copied back into `packages/private-vote-sdk/tests/vectors/`.
