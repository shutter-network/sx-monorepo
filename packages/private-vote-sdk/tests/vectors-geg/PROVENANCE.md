# geg conformance vectors — vendored copy

**Do not hand-edit.** Regenerate with:

```bash
node scripts/sync-geg-vectors.mjs [path-to-geg-repo]
```

| | |
|---|---|
| Source repo | `generalised-el-gamal` |
| Source path | `tests/vectors/` |
| Commit | `02b13ed0989bbe3556d9fc11015a622b95ee9d7d` |
| Commit date / subject | 2026-08-10T22:15:17+05:30 feat: implement tally-stalled functionality to enhance election integrity, allowing for recovery from abandoned tallies by introducing admin retry capabilities and updating relevant frontend components |
| Vectors | 24 across 10 categories |

- `attestation/` — 6
- `ballot/` — 4
- `budget/` — 2
- `decrypt-share/` — 4
- `dleq/` — 1
- `encrypt/` — 1
- `flow/` — 1
- `or/` — 1
- `schnorr/` — 2
- `tally/` — 2

## Why these are checked in

`tests/geg-parity.test.ts` is a **blocking gate**: it proves this vendored fork
of the SDK has not diverged from what geg's Python implementation verifies. A
gate that skips when a sibling checkout is missing is not a gate, so the vectors
live here and CI runs them unconditionally.

## Why 13 of them duplicate `tests/vectors/` byte-for-byte

Deliberately, and the duplication is load-bearing — do not "deduplicate" it.

`scripts/gen-vectors.ts` writes to `tests/vectors/` (`npm run gen-vectors`). If
the parity gate read the shared vectors from there, then regenerating them would
silently repoint the gate at freshly-produced *local* bytes: it would keep
passing while no longer testing geg's corpus at all. This directory is the
pinned, geg-owned copy, and the only thing that may rewrite it is
`sync-geg-vectors.mjs`.

Two of the shared 15 (`decrypt-share/share_basic.json`,
`tally/tally_basic.json`) differ from our copies in their `dleq_proof` bytes
only — DLEQ proofs are randomized, so each repo generated a valid proof of an
identical statement with a different nonce. Cross-verifying both is exactly what
the gate checks.

Every file here is asserted: `geg-parity.test.ts` fails if any vector on disk
went unchecked, so there is no dead weight by construction.
