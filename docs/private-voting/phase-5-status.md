# Phase 5 — voter UI integration

Branch: `feat/shutter-elgamal-vote-modal`
Parity gate: green (23/23 in 0.32s).

## What landed

Client-side ballot encryption for `privacy === 'shutter-elgamal'`
proposals on the offchain (Snapshot.org) network, using the vendored
`@snapshot-labs/private-vote-sdk`.

### Files
- `apps/ui/src/helpers/teBallot.ts` (new) — `ensureCurvesInit`,
  `pseudonymFor`, `buildTeBallotEnvelope`. Wraps the SDK's
  `initCurves`, `schnorrKeygen` and `buildBallot`. Variant A exact B=1
  (single-choice) only. Hex-encodes every byte field. Drops `sk` on
  return.
- `apps/ui/src/networks/offchain/actions.ts` — `vote()` branches on
  `proposal.privacy === 'shutter-elgamal'` and substitutes the
  envelope object into the `choice` slot. The reason field is force-
  cleared (the hub rejects reasons in private mode).
- `apps/ui/src/networks/offchain/api/{queries,types,index}.ts` — the
  proposal fragment now selects `te_config te_mpk te_committee_pks
  te_threshold_t te_threshold_n te_keyper_urls te_keyper_addresses
  te_aggregate`; `formatProposal` propagates them. `ApiProposal.privacy`
  widened to `'shutter' | 'shutter-elgamal' | ''`.
- `apps/ui/src/types.ts` — `Proposal` gains the same `te_*` optional
  fields.
- `apps/ui/package.json` — adds `@snapshot-labs/private-vote-sdk`
  (workspace dep).
- `apps/ui/public/.gitignore` — ignores `blst.{js,wasm}` (build
  artifacts).
- `packages/private-vote-sdk/scripts/copy-wasm.mjs` — also mirrors
  `blst.js` and `blst.wasm` into `apps/ui/public/`. The browser SDK's
  loader (`get-blst.ts`) injects a `<script src="/blst.js">` tag, so
  the WASM glue must live at the Vite public root.

### Wire format (single-choice TE ballot)
```jsonc
choice: {
  electionId: "0x...32 bytes",
  pseudonym:  "0x...32 bytes (= keccak256(voter || proposalId))",
  vk:         "0x...48 bytes G1",
  ciphertexts: [{ c1: "0x...96", c2: "0x...96" }, ...],
  zkProof:        "0x...",
  voterSignature: "0x...80",
  wrAttestation:  "0x"
}
```
The shape is wire-compatible with snapshot.js's existing weighted-vote
path (`Record<string, number>` already permitted by `getSdkChoice`),
so no upstream snapshot.js change is required.

## Out of scope for this commit (deferred)

- **Eager `ensureCurvesInit()` on Vote modal open.** Currently the
  WASM (~700 KB) loads on submit click; users on slow links see a
  noticeable pause. Not a correctness issue. To be added when wiring
  Phase 8's "verify tally" button.
- **`SelectPrivacy.vue` extension and admin space settings.** These
  are Phase 7 work.
- **`ProposalResults.vue` private-tally badge.** Phase 8 — together
  with the verify-tally button.
- **Multi-choice / approval / weighted shutter-elgamal.** Out of v1.

## Validation
- Parity gate: 23/23 pytest green; SDK fixtures byte-equivalent.
- Type-check / runtime lint blocked by the absence of `bun` on the
  build host; the parity gate covers crypto correctness.

## Next: Phase 6 — keyper deployment / E2E.
