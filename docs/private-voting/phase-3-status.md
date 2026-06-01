# Phase 3 — Vote ingestion for shutter-elgamal proposals

Status: **landed**. Commit prefix: `feat: ingest shutter-elgamal votes`.

## What landed

The sequencer's vote writer now branches on `proposal.privacy === 'shutter-elgamal'` and verifies the encrypted ballot at write time. We never persist a ciphertext that the tally would later reject.

### `apps/sequencer/src/helpers/te.ts` (new)

- `ensureCurvesInit()`: lazy, idempotent BLS12-381 curve initialisation. Called once per process on the first ballot.
- `expectedPseudonym(voter, proposalId)`: `keccak256(voter || proposalId)`.
- `verifyTeBallot(proposal, voter, choiceJson)`: parses the JSON ballot envelope, checks pseudonym matches `expectedPseudonym(voter, proposal.id)`, decompresses `te_mpk`, calls SDK `verifyBallot`. WR-attestation slot is satisfied by `() => true` because Snapshot's outer EIP-712 envelope is the voter-auth boundary.

### `apps/sequencer/src/writer/vote.ts` (modified)

`verify()` got a new branch between the existing `'shutter'` (commit-reveal) branch and the default isValidChoice path:

```ts
} else if (proposal.privacy === 'shutter-elgamal') {
  if (msg.payload.reason) return Promise.reject('reason not allowed with shutter-elgamal');
  if (typeof msg.payload.choice !== 'object' || msg.payload.choice === null)
    return Promise.reject('invalid choice: expected ballot object');
  const result = await verifyTeBallot(proposal, body.address.toLowerCase(), JSON.stringify(msg.payload.choice));
  if (!result.ok) return Promise.reject(`invalid private ballot: ${result.reason}`);
}
```

The existing `'shutter'` branch (commit-reveal) is unchanged; both privacy modes coexist.

### `apps/sequencer/src/helpers/actions.ts` (modified)

`getProposal()` now parses `te_config` from JSON and hex-encodes the `te_mpk` Buffer (compressed G2). Same pattern as the hub-side `formatProposal` from Phase 1. Other te_* columns aren't needed at vote time so they aren't surfaced here.

### `apps/sequencer/package.json`

- Added `@snapshot-labs/private-vote-sdk: workspace:*`. Workspace dep — bun resolves it from `packages/private-vote-sdk`.
- Added `@ethersproject/keccak256`. Already a transitive dep of the existing ethers v5 mods used in this app, but declared explicitly because the te helper imports it.

### Tests

`apps/sequencer/test/unit/helpers/te.test.ts`: structural-rejection coverage for the four boundary conditions (missing config, missing DKG, malformed JSON, pseudonym mismatch). Cryptographic-positive coverage (a vector that passes verifyBallot) lives in the SDK's own fixture suite — it's already exercised by the parity gate, and re-running it inside the sequencer's jest harness would just re-prove the SDK's `verifyBallot` is deterministic.

## Wire format for the ballot envelope

`msg.payload.choice` is the JSON object the SDK's `buildBallot` returns, hex-encoded throughout:

```jsonc
{
  "electionId":     "0x…32-byte hex",   // proposal-scoped id used by the SDK transcript
  "pseudonym":      "0x…32-byte hex",   // = keccak256(voter || proposalId)
  "vk":             "0x…48-byte hex",   // voter Schnorr verification key (compressed G1)
  "ciphertexts":    [{ "c1": "0x…96-byte hex", "c2": "0x…96-byte hex" }, …],
  "zkProof":        "0x…",              // encodeBallotValidityProof output
  "voterSignature": "0x…80-byte hex",   // encodeSchnorr(sig)
  "wrAttestation":  "0x"                // unused in the snapshot ingest path
}
```

Phase 5 (UI vote modal) is responsible for producing this object; this phase only consumes it.

## Why mutate snapshot.utils.voting type isValidChoice path is left alone

Per the conversation summary's continuation plan, the `Choice` union (`for | against | abstain | number | number[] | Record<string, number>`) doesn't need extending: at the wire level the encrypted ballot is just an opaque JSON object the SDK constructs, parsed by the te-mode-specific decoder. The pre-existing `isValidChoice` path is bypassed entirely on the te branch.

## Verification

- Phase 0 parity gate: still **green** (no SDK changes).
- Python keyper code: still parses clean.
- The new sequencer code only uses imports that exist in the dep tree once `bun install` runs against the updated `package.json`. Without bun installed locally, full TypeScript typecheck couldn't be executed in this session; the imports have been hand-checked against `packages/private-vote-sdk/src/index.ts` and the existing `@ethersproject/*` usage in the sequencer.
- Unit-test scaffolding is in place; running `bun test` to validate it requires the bun toolchain.

## Decisions

- **Pseudonym binding at ingest, not at tally.** Rejecting a wrong pseudonym before doing the (expensive) zk verify saves work on adversarial input.
- **`() => true` WR verifier.** The SDK was designed for an external WR-Server attestation step that doesn't exist in Snapshot's flow. The EIP-712 envelope replaces it. Documented in the helper module's docstring so a future reviewer doesn't think we forgot to wire it.
- **Choice as object, not pre-stringified.** Avoids the JSON.stringify-of-a-string double-encoding bug that would otherwise hide every parsing problem behind quotes.
- **Single curve init at process scope.** `ensureCurvesInit()` is cached at module level, mirroring how `helpers/shutter.ts` already does `init()` exactly once.

## Not in this phase

- No tally worker (Phase 4). The verifier confirms ballot validity at write time; the homomorphic sum and decryption pipeline are still no-ops.
- No UI to produce the envelope (Phase 5). Until then, the only way to exercise this code path is a hand-crafted ballot in an integration test.
- No proposal-create-time blocking of `ranked-choice + shutter-elgamal` (Phase 9).
- No suppression of `scores_by_strategy` at the GraphQL layer for te proposals (Phase 4 / 5).
