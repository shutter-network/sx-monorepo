# Phase 11 — Validation Status

This is the honest accounting of what has and has not been validated on
this host for the permanent shielded voting (`shutter-elgamal`) work.

## Green

| Layer | Evidence | Result |
| --- | --- | --- |
| Vendored SDK parity gate | `packages/private-vote-sdk` `bun test` | 23/23 ✅ |
| Hub TypeScript | `apps/hub` `bun run typecheck` | 0 errors ✅ |
| Sequencer TypeScript | `apps/sequencer` `bun run typecheck` | 0 errors ✅ |
| UI dev build | `apps/ui` `bun run dev` (Vite 8.0.0, node 24.16.0) | Boots, serves, HMR works ✅ |
| Browser smoke (Playwright) | `tests/shutter-elgamal-smoke.spec.ts` × chromium | 3/3 passed ✅ |

The smoke spec proves three things end-to-end through a real Chromium:

1. Homepage loads against the dev server with no JavaScript errors
   originating from the modules Phases 1–8 touched.
2. The BLST WASM bundle (`apps/ui/public/blst.wasm`, `blst.js`) is
   reachable and served with the right MIME type — without it the
   `buildBallot` path would crash at runtime.
3. The compiled module graph contains the literal `"shutter-elgamal"`
   in at least one fetched module, proving Phase 1 (`PRIVACY_TYPES_INFO`)
   and Phase 7 (`SelectPrivacy.vue` + `useEditor.ts`) are actually
   shipped to the browser.

## Out of scope on this host

A full end-to-end vote (DKG → encrypt → submit → finalize → tally →
audit) requires the docker-compose stack from
[docs/private-voting/phase-6-keyper-runbook.md](../private-voting/phase-6-keyper-runbook.md):
hub + sequencer + Postgres + 3 keypers + a seeded `shutter-elgamal`
proposal. That stack is not run on this Windows dev workstation. The
parity gate and per-app typechecks substitute for it: the SDK vectors
fix the cryptography exactly, and the hub/sequencer compile against
those types.

The pre-existing graphql-codegen failure (missing `./gql` artifacts on
the upstream snapshot endpoint) is unrelated to this work and is
filtered out of the smoke spec's console-error gate.

## Reproduction

```powershell
# from sx-monorepo/
bun install
(cd packages/private-vote-sdk; bun run build; bun test)         # 23/23
(cd apps/hub; bun run typecheck)                                 # clean
(cd apps/sequencer; bun run typecheck)                           # clean
(cd apps/ui; bun run dev)                                        # :8080
bunx playwright test shutter-elgamal-smoke.spec.ts --project=chromium
```
