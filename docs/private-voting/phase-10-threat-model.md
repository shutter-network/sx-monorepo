# Threat model — permanent shielded voting

Phase 10 deliverable. Companion to `phase-6-keyper-runbook.md`. Audit
target = Snapshot offchain proposals with `privacy: 'shutter-elgamal'`.

## Trust assumptions

| Assumption | Why it holds (or doesn't) |
| --- | --- |
| BLS12-381 discrete log is hard | Standard pairing-curve assumption; backed by 128-bit security estimates. |
| BLST WASM matches the audited BLST native code | Vendored from the audited `@snapshot-labs/private-vote-sdk`; parity gate (`scripts/parity-gate.mjs`) cross-checks 23 fixtures byte-for-byte against a Python reference (`thresholdELGamal/.venv`). |
| Strictly fewer than `t+1` keypers collude | t=1, n=3 ⇒ any single keyper learning a vote breaks privacy. The committee is split across three independent operators. |
| Voter wallet is not compromised | The voter's EIP-712 signature is the auth boundary. A compromised wallet can already vote on the user's behalf in Snapshot; private mode does not aim to fix that. |
| Hub is not a fully trusted party | Hub can refuse to publish a ballot, but cannot decrypt one. It also cannot forge signatures on a voter's behalf — every ballot carries the user's EIP-712 signature, which the sequencer verifies against the registered voter address. |
| Sequencer is honest about WHICH ballots it counted | The list of accepted ballots (and their EIP-712 signatures) is published at tally time so external auditors can recompute `te_aggregate` from raw ballots themselves. A sequencer that silently drops ballots is a censorship attack, not a confidentiality break. |

## Adversary model

### A1 — Network observer (passive)
Sees ballot envelopes in transit. Each envelope is a freshly
randomised ElGamal ciphertext bundle plus public signatures. Linkable
to the voter's wallet (the EIP-712 signature is in the envelope), but
the candidate vector is information-theoretically masked by the
per-ballot randomness.

**Mitigated.** No new exposure beyond Snapshot's existing transport
visibility (which already reveals voter ↔ proposal links).

### A2 — Single malicious keyper
Holds 1 of 3 partial keys. Knows nothing about voter choices unless
it colludes with another keyper.

**Mitigated by t=1.** The DLEQ proofs in the partial decryption shares
let any auditor catch a keyper that submits a malformed share — the
SDK's `verifyDecryptionShare` (re-run client-side via the Phase 8
"Verify tally" button) returns false on tamper.

### A3 — Two colluding keypers
Together hold `t+1=2` shares. They CAN decrypt the per-candidate
ciphertext sum. They cannot decrypt individual ballots — homomorphic
aggregation is performed before any keyper sees the ciphertexts to
decrypt.

**Mitigated by aggregation gate.** The sequencer ONLY POSTs the
aggregate to keypers; per-ballot ciphertexts are never exposed to the
keypers (they are deleted after `te_aggregate` is finalised). An
auditor can replay the aggregation from the published ballot list,
confirming no individual ballots were ever sent for decryption.

### A4 — Malicious sequencer
Could:
- Drop ballots (censorship). Detectable: the published voter list omits
  votes that the user proves they signed. Snapshot's existing IPFS
  ballot pinning means this is a public defection.
- Forge ballots? No — every ballot carries a Schnorr signature over a
  binding-to-`(electionId, pseudonym, vk)` preimage, plus the outer
  EIP-712. The sequencer would need both the voter's wallet AND a
  valid Schnorr keypair the voter registered for this proposal.
- Lie about `te_aggregate`. Detectable: anyone can recompute it from
  the published ballot list; mismatch means tampering.

**Mitigated by client-side recompute.** Phase 8 only currently
recomputes from the hub-published shares; a future Phase 11 should
also recompute the aggregate from the ballot list itself.

### A5 — Malicious voter, ballot stuffing
The SDK's `buildBallot` enforces a budget proof: for Variant A exact
B=1, the homomorphic sum of the ciphertext bundle must encrypt
exactly 1. A voter who tries to encode `[2, 0, 0, ...]` produces a
ciphertext sum of 2; the validity proof fails verification at
`apps/sequencer/src/helpers/te.ts:verifyTeBallot`, and the ballot is
rejected at ingest.

**Mitigated by always-on ingest verification.** The sequencer's
`writer/vote.ts` calls `verifyBallot` before any DB write; there is
no batch path that bypasses it.

### A6 — Malicious voter, replay across proposals
Each ballot binds the proposal id into both `electionId` and
`pseudonym = keccak256(voter || proposalId)`. Replaying a ballot from
proposal A on proposal B fails the pseudonym check and the Schnorr
signature check.

**Mitigated.**

### A7 — Compromised WR-Server
Out of v1 scope. The current SDK ships a `() => true` WR verifier
because the EIP-712 envelope IS the auth boundary in Snapshot.
Switching on a real WR-Server later means swapping the verifier in
`apps/sequencer/src/helpers/te.ts`; the rest of the pipeline is
unchanged.

### A8 — Long-term key compromise
The keypers hold long-term BLS signing keys + DKG-derived per-proposal
shares. A future leak does NOT retroactively compromise past tallies
under the t=1, n=3 model unless ≥2 of the leaked keys are from the
same proposal's committee. Forward secrecy is per-proposal: each new
proposal runs a fresh DKG.

## Out-of-scope

- DOS against the hub or keypers (denial of availability is a separate
  concern; private voting does not weaken it).
- Side-channel attacks against the keyper hosts.
- Coercion resistance beyond what the SDK's WR-attestation slot offers.
  v1 ships with the slot wired to a constant-true verifier; coercion
  resistance ↔ a real WR-Server is a future phase.
- Quantum adversaries. BLS12-381 is broken by Shor's algorithm; tally
  confidentiality is post-quantum-vulnerable. This matches the
  threat model of every other BLS12-381 system in production.

## Operator policy

- Three keypers run by three independent organisations.
- Keyper hosts must publish their public address; rotating it is a
  manual change to a space's `te_keyper_addresses` allow-list and
  applies only to NEW proposals (existing proposals keep their
  committee).
- Any keyper that produces a verification failure during a tally
  audit (Phase 8 button shows a red mismatch) is removed from the
  allow-list before the next proposal.

## Audit checklist

For external reviewers:

1. Run `node scripts/parity-gate.mjs` — confirm 23/23 SDK fixtures match
   the Python reference.
2. Inspect `apps/sequencer/src/writer/vote.ts` — confirm `verifyBallot`
   is called on every shutter-elgamal write.
3. Inspect `apps/sequencer/src/scores.ts:runShutterElgamalTally` —
   confirm aggregation runs before any per-keyper trigger; confirm
   only the aggregate is exposed to keypers.
4. Inspect `apps/hub/src/te.ts` — confirm the allow-list is consulted
   on `/te_decryption_share` and `/te_dkg`.
5. Open a closed shutter-elgamal proposal in the UI, click "Verify
   tally". Confirm the recomputed totals match the published scores.
