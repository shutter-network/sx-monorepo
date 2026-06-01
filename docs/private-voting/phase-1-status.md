# Phase 1 — Schema for shutter-elgamal proposals

Status: **landed**. Commit prefix: `feat: schema for shutter-elgamal proposals`.

## What landed

Schema additions, type-union extension, and API exposure. **No behavior change** — the new fields are read by nothing yet. Phases 2 and 3 wire them up.

### SQL (mirrored across both schemas)

`apps/hub/src/helpers/schema.sql` and `apps/sequencer/test/schema.sql`:

- `proposals` gains seven nullable columns: `te_config JSON`, `te_mpk VARBINARY(96)`, `te_committee_pks JSON`, `te_threshold_t INT`, `te_threshold_n INT`, `te_keyper_urls JSON`, `te_aggregate JSON`. All NULL unless the proposal is `privacy='shutter-elgamal'`. `te_mpk` is also NULL between proposal creation and DKG completion.
- New table `te_decryption_shares (proposal_id, keyper_index, candidate, sigma, proof_e, proof_z, posted_at)`. Append-only — the `(proposal_id, keyper_index, candidate)` PK enforces one share per keyper per candidate.

### Type unions

- `packages/sx.js/src/types/index.ts`: `Privacy = 'shutter' | 'shutter-elgamal' | 'none'`.
- `apps/ui/src/types.ts`: same.

### UI surface (no logic yet)

- `apps/ui/src/helpers/constants.ts`: `PRIVACY_TYPES_INFO['shutter-elgamal']` with copy describing permanent encryption.
- `apps/ui/src/composables/useSpaceSettings.ts`: `validPrivacyTypes` accepts the new mode.

### API exposure

- `apps/hub/src/graphql/schema.gql`: seven new optional fields on `Proposal`.
- `apps/hub/src/graphql/helpers.ts → formatProposal`: parses the JSON columns, hex-encodes the `te_mpk` Buffer (`0x` prefix, compressed-G2). Helper `bytesToHex` added.

The existing `votes.choice` column is unchanged — the encrypted-ballot blob fits the existing `JSON` type. Phase 3 documents the new shape inline at the writer.

## Voting-types Choice union

Not changed in this phase. The existing `Choice` union (`'for' | 'against' | 'abstain' | number | number[] | Record<string, number>`) already covers the JSON blob the UI will pass for shutter-elgamal proposals — at the wire level the encrypted ballot is just an opaque JSON object the SDK constructs, and the sequencer parses it with a private-mode-specific decoder rather than going through `Choice` typing. Documented in the Phase 3 writer.

## Verification

- The Phase 0 parity gate stays green (no SDK change).
- Type-union extension is internally consistent: a workspace grep for the literal pattern `'shutter' | 'none'` returns no matches.
- Schema SQL syntactically valid (mirrors existing `JSON DEFAULT NULL` and `VARBINARY` patterns already in the file).

## Decisions settled (guide §6)

- Pseudonym: deferred to Phase 3 (writer enforces uniqueness at storage time).
- Decryption shares public artifacts: **yes**, exposed via the GraphQL `Proposal.te_*` and a future `proposal/{id}/te_shares` endpoint (Phase 4 / Phase 8). Anyone can re-verify.
- `te_aggregate` is JSON, not VARBINARY — easier to inspect and the size is bounded by `numCandidates × 192 bytes` of compressed-G2 hex, dwarfed by the existing `strategies` JSON.

## What is intentionally NOT in this phase

- No `te_dkg_status` enum column. Proposal state derives from `te_mpk IS NULL` (DKG pending) vs `te_mpk IS NOT NULL` (voting open). Adding a redundant status column would just be one more place to keep in sync.
- No production migration files. The schemas in this repo are dropped/recreated for tests; production rolls a separate migration pipeline whose ALTERs mirror these CREATE-TABLE changes one-to-one. The migrations themselves are operational and live with the deployment, not the source tree.
