# Permanent private voting (`shutter-elgamal`)

> **Alpha.** The UI surfaces an "Alpha" tag on the **Permanent private voting** privacy option.

The entry point for Snapshot's **permanent private voting**: a proposal privacy mode,
`privacy: 'shutter-elgamal'`, in which every ballot is encrypted in the browser and **stays
encrypted forever**. Only the final tally is ever revealed, and the Snapshot backend cannot decrypt
an individual vote at any point — not during voting, not after, not with its database.

It is built on **linearly-homomorphic threshold ElGamal over BLS12-381**. Voters encrypt under a
committee master public key, the ciphertexts are summed homomorphically, and a committee of
independent **keypers** jointly decrypt only the sum.

**Snapshot does not run the committee.** The keypers and their coordinator are the
[generalised-el-gamal][geg] protocol's own services, run by separate operators; this repository is
the data layer they read ballots from and write results to. That split is the security property —
see [`architecture.md`](./architecture.md) for why, and [`architecture-legacy.md`](./architecture-legacy.md)
for the single-writer design it replaced.

[geg]: https://github.com/shutter-network/generalised-el-gamal

---

## Contents

- [How it works](#how-it-works)
- [Where the code lives](#where-the-code-lives)
- [Crypto parameters](#crypto-parameters)
- [Running it](#running-it)
- [Lifecycle of a proposal](#lifecycle-of-a-proposal)
- [Security model](#security-model)
- [Operational rules worth knowing](#operational-rules-worth-knowing)
- [Troubleshooting](#troubleshooting)
- [Reference](#reference)

---

## How it works

```mermaid
flowchart LR
    A[Voter browser] -->|encrypted ballot + ZK proof| S[Sequencer]
    S -->|ballots, config| DB[(MySQL)]
    H[Hub] --- DB
    H -->|master public key| A
    L[te-data-layer<br/>translator] --- H
    C[Coordinator<br/>protocol repo] -->|drives ceremony| L
    K[Keypers 1..n<br/>protocol repo] -->|read ballots| L
    K -->|signed aggregate + shares| C
    C -->|signed result| L
```

1. **Key generation.** When a private proposal is created, the sequencer freezes the committee onto
   it and the coordinator drives a Feldman-VSS distributed key generation. The keypers publish a
   single master public key (`te_mpk`); no party ever holds the full secret. This must complete
   **before voting opens** — a key that arrives later cannot match the ballots, so the proposal is
   terminally dead rather than merely late.
2. **Voting.** The browser encrypts under `te_mpk`, attaches a zero-knowledge proof that the ballot
   is well-formed (per-candidate range plus an exact budget), signs it with the voter's wallet
   (EIP-712), and carries an eligibility credential minted by the hub binding that ballot's voting
   power. The sequencer verifies every ballot at ingest.
3. **Aggregation.** After close, **every keyper independently re-derives** the voting-power-weighted
   sum from the same ordered ballots and submits it signed. The artifact becomes canonical only when
   a quorum submits it **byte-identically**.
4. **Decryption.** Each keyper publishes a partial decryption share with a DLEQ proof. The
   coordinator recovers the plaintext totals by Lagrange interpolation and baby-step-giant-step,
   signs them, and publishes. The hub verifies the signature; the sequencer mirrors the scores.

Step 3 is the one that changed, and it is the point of the whole design. The sequencer used to sum
the ballots alone, which meant isolating one voter's ballot required compromising one process.
Now it requires corrupting a majority of the committee.

A voter with voting power `N` is counted `N` times by scaling their ciphertexts by `w = round(vp)`
before the sum — no change to the ballot cryptography. Voting power below 0.5 would round to weight 0 
and contribute nothing, so such a vote is refused at ingest rather than accepted and dropped.

---

## Where the code lives

| Component | Path | Role |
| --- | --- | --- |
| Client crypto SDK | `@shutter-network/urban-verified-crypto` | Ballot construction, ZK proofs, verification, tally recovery. Published package, BLST WASM. |
| Hub | [apps/hub](../../apps/hub) | GraphQL/REST. Storage of record for ballots, DKG results, aggregates, shares, results. Verifies every protocol write. |
| Sequencer | [apps/sequencer](../../apps/sequencer) | Vote ingestion and ballot verification; freezes the committee onto each proposal; mirrors published totals into `scores`. |
| Translator | [apps/te-data-layer](../../apps/te-data-layer) | Presents the hub to the protocol as its data layer, over the port contract. |
| Voter UI | [apps/ui](../../apps/ui) | Builds encrypted ballots locally; the verify-tally panel; the stall notice and admin retry. |
| Cross-language vectors | [packages/geg-parity](../../packages/geg-parity) | TS ⇄ Python parity for the crypto primitives. |
| Committee | **not in this repo** | Keypers and coordinator live in the protocol repository, run by independent operators. |

---

## Crypto parameters

| Parameter | Value |
| --- | --- |
| Curve | BLS12-381 (ElGamal in G₂, Schnorr in G₁) |
| Threshold | `t = 2, n = 3` — `t` is the **quorum**, the number of keypers required |
| Ballot variant | Variant A, exact budget `B = 1` (single-choice) or `B = 100` (weighted) |
| DKG | Feldman verifiable secret sharing |
| Write authorisation | `GEG-DKG-RESULT-v1`, `GEG-AGGREGATE-v1`, `GEG-DECRYPT-SHARE-v1`, `GEG-RESULT-v1`, wrapped in `GEG-REQUEST-v1` |
| Digest parity | Vectors generated by the protocol's Python, in `apps/hub/test/fixtures/geg-*.json` |

### How much voting power a ballot can carry

Three ceilings, and they are not independent — `budget` sets two of them:

| Budget | Split granularity | Max weight per voter | Max choices |
| --- | --- | --- | --- |
| 1 (any non-weighted type) | n/a | 1,000,000 | 1,250 |
| 10 | 10% steps | 100,000 | 227 |
| **100** (default) | whole percents | **10,000** | **24** |

`maxWeight = floor(1_000_000 / budget)`, because the protocol caps
`budget x maxWeight`; the choice limit is `candidates x (budget + 1) <= 2500`.
Raising precision therefore costs both headroom and choices.

Two consequences that change results and are easy to miss:

- **Voting power above the ceiling is counted at the ceiling.** A holder of 25,000
  and one of 2,500,000 vote identically at budget 100. The tally stays internally
  consistent, so recomputing it reproduces the capped figure and reveals nothing —
  which is why the verify panel now lists every capped ballot and what it held.
- **Private voting closes one second before public voting.** The protocol's window is
  half-open (`start <= t < end`) where Snapshot's is closed, and the committee re-checks
  the window at tally time. A vote timestamped exactly at `end` would be accepted by
  Snapshot, excluded by the committee, and — because the verify panel recomputes over
  every published ballot — would report the whole tally as unverified. Private proposals
  therefore use the protocol's boundary.
- **Voting power below 0.5 cannot vote on a private proposal.** It would round to zero
  weight and contribute nothing, so the vote is refused at ingest with a message saying
  so. It is refused rather than accepted-and-dropped because a zero-weight ballot never
  enters the keypers' feed at all — it would appear in neither the admitted set nor the
  exclusion list, leaving a voter who believes they voted with no way to discover
  otherwise. The same holding votes normally on a public proposal.

Why integers at all, when public voting uses floats: the tally is recovered by
searching for a discrete logarithm over a bounded range, so the plaintext has to be
a small non-negative integer that the search can land on. Fixed-point is possible
but self-defeating — scaling weights by 100 for two decimal places multiplies the
search bound by 100, and to stay under the protocol cap `maxWeight` would fall from
10,000 to 100. The million is an allowance spent on *either* precision or magnitude.

**None of this applies to public proposals.** Public weighted voting has no budget:
a voter submits arbitrary relative integers and each choice takes
`share / total x vp` at full float precision, uncapped. The budget exists here
because the ballot's validity proof must show the ciphertexts sum to a fixed public
constant.

**On the threshold notation.** `t = 2, n = 3` and "2-of-3" mean the same thing: two keypers must
cooperate. Older notes in this directory say `t = 1, n = 3` for the same committee, counting
tolerated faults instead of the required quorum. Mixing the two is what produces a config rejected
as *"threshold must be a majority"*.

---

## Running it

See **[`RUNNING.md`](../../RUNNING.md)** at the repository root — a copy-paste walkthrough covering
both repositories: every environment file, both stacks, creating a proposal, voting, and watching
the tally publish.

The three "Running it" sections that used to be here described a compose file that started the
committee alongside Snapshot's services. That arrangement gave one `docker compose up` the power to
read every ballot, and it no longer exists.

---

## Lifecycle of a proposal

| Stage | What must be true |
| --- | --- |
| Creation | Opens at least `MIN_DKG_LEAD_TIME_S` (180s) ahead; every keyper reachable, since the sequencer resolves the committee from each `/status` |
| DKG | Needs **every** member, not a quorum. Failure is terminal at `voting_start` |
| Voting | `te_mpk` present; each ballot verified at ingest and carrying an eligibility credential |
| Aggregation | Past `votingEnd`; a quorum of byte-identical artifacts makes one canonical |
| Decryption | A canonical aggregate exists; shares are DLEQ-verified against it |
| Result | Signed by the coordinator, verified against the frozen `resultPublisherAddress` |
| Mirror | The sequencer divides by the budget and writes `scores`, `scores_state = 'final'` |

Two states are worth naming because they are visible to users:

- **Stalled** — the committee could not finish. Persisted, so a coordinator restart does not resume
  it; an admin clears it from the proposal page. The two directions are signed by different
  identities on purpose.
- **DKG failed** — voting opened with no key. Terminal, and **derived on read** rather than stored:
  `privacy ∧ ¬te_mpk ∧ now > start`.

---

## Security model

Threshold `t = 2, n = 3`: two keypers must cooperate to open a tally; one alone learns nothing.

| Adversary | Outcome |
| --- | --- |
| Network observer (passive) | Freshly-randomised ciphertexts and public signatures. The candidate vector is information-theoretically masked. No exposure beyond Snapshot's existing voter↔proposal links. |
| Single malicious keyper | Holds 1 of 3 shares — learns nothing. Malformed shares are caught by the DLEQ proof, re-run by the "Verify tally" button. |
| Two colluding keypers | Can decrypt the per-candidate **aggregate** only. Individual ballots are never decrypted by anyone. |
| Malicious hub or sequencer | Cannot forge ballots (Schnorr + EIP-712), cannot decrypt, and **cannot produce the canonical aggregate** — it only records what keypers submit and promotes what a quorum agrees on. Hiding a ballot now requires corrupting a majority of the committee. |
| Ballot stuffing | The budget proof requires the ciphertext sum to encrypt exactly `B`. Over-budget ballots fail verification at ingest. |
| Replay across proposals | Each ballot binds the proposal id into `electionId` and `pseudonym = keccak256(voter ‖ proposalId)`. |
| Deleting an inconvenient tally | **Not prevented.** A private proposal is deletable on the same terms as a public one, at any point, by its author, an admin, or a moderator. Unlike a public tally it is not reconstructible afterwards — accepted deliberately. |
| Long-term key compromise | Forward secrecy is per-proposal; each proposal runs a fresh DKG. |

**Out of scope:** DoS and availability, host side-channels, coercion resistance, and quantum
adversaries (BLS12-381 confidentiality is post-quantum-vulnerable, as with every BLS12-381 system).

**Known limitation — committee discovery.** `TE_KEYPERS` holds URLs; each address is read from that
keyper's `/status` once per sequencer process and frozen into the proposal. Over HTTPS the
certificate anchors that identity; over plain HTTP the network path does. Use HTTPS keyper URLs in any real deployment.

**Operator policy:** three keypers run by three independent organisations, each holding its own
signing key and its own encrypted state directory. A keyper that produces a verification failure
during an audit is removed from the committee before the next proposal.

---

## Operational rules worth knowing

Each of these has produced a confusing failure at least once:

- **A keyper must be reachable when a private proposal is created**, because the committee is
  resolved then. It fails loudly at creation rather than producing a proposal that dies later.
- **Two keyper URLs must not report the same address.** A committee of "3" that is really 2 keys
  makes `t = 2` satisfiable by one operator. Refused at creation.
- **`GEG_API_URL` on a keyper is a base URL** — it appends `/port` itself. Including the suffix
  yields `/port/port` and every read 404s.
- **Losing a keyper's state directory loses its share.** If that puts the committee below quorum,
  those elections can never be decrypted, by anyone.
- **A private proposal can be deleted at any point**, like a public one, and its
  committee artifacts go with it. Unlike a public tally, nothing can reconstruct it
  afterwards.
- **Editing is allowed until `start`**, including inside the DKG lead-time window once the key
  exists.

---

## Troubleshooting

- **"proposal does not yet have a finalised threshold key"** → the DKG has not completed. If
  `start` has already passed it never will; the proposal is terminally dead and the UI shows a DKG
  failure notice.
- **Proposal stuck on "Finalizing results"** → the scores endpoint was never called or could not be
  reached. `curl -sL localhost:3000/api/scores/<id>` should return `{"result":true}`; if the redirect
  target is not resolvable from a browser, fix `SEQUENCER_PUBLIC_URL`.
- **`TE_KEYPERS entry "…" looks like "address@url"`** → the config takes URLs only now; addresses are
  read from `/status`.
- **Tally stalled** → the notice names three possible causes and asserts none, because the stored
  flag is a boolean. Which one it was is in the coordinator's log: `grep abandoned`.
- **Committee writes rejected as `not_a_registered_keyper`** → the address recovered from the
  signature is not in the proposal's frozen config. Usually a keyper key rotated after the proposal
  was created; the frozen config is deliberately immutable.

