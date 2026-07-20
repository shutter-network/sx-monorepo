# Automated Keyper Bearer Token Bootstrap

## Status

Supersedes the **Token Management** and **Implementation Option: Coordinator-Distributed
Peer Tokens** sections of [`keyper-bearer-token-auth.md`](./keyper-bearer-token-auth.md).
That doc's per-endpoint threat table (SSRF, share exfiltration, ceremony-wipe severities)
is unchanged and still the reference for *why* auth is needed. This doc replaces *how
tokens get from an operator's head into `KEYPER_API_TOKEN`/`KEYPER_PEER_TOKENS`* — today
that's manual (`python -c "import secrets..."`, share out-of-band, paste into `.env`).
This design automates it over the network, end-to-end encrypted and signed, with no new
manual step per token — only a one-time, non-secret identity exchange.

---

## Problem with manual token sharing

- O(n²) or O(n) operator-to-operator exchanges depending on baseline vs. coordinator-distributed variant — still a human copy-paste step every time a keyper is added or a token rotates.
- No rotation in practice, because rotation means re-doing the manual exchange.
- Auto-dkg (`auto_dkg.py`) restart already loses `KEYPER_PEER_TOKENS` if it's ever made dynamic instead of env-var-static.

## What this design must guarantee

| Property | Why | Mechanism |
|---|---|---|
| **Confidentiality** | Multi-operator deployment — each keyper runs on a different org's infra; TLS protects one hop, not a proxy/log/APM tool inside an operator's own network that we don't control | Payload-level encryption (X25519 sealed box), independent of TLS |
| **Authenticity** | A public encryption key is, by definition, public — anyone can encrypt *something* to it. Encryption alone does not stop an attacker from injecting an arbitrary self-chosen token | Coordinator signs the payload (EIP-191) before encrypting; keyper verifies against a pinned `COORDINATOR_ADDRESS` after decrypting |
| **Anti-replay / anti-misdirection** | A captured valid envelope shouldn't be replayable later, or against a different keyper | `nonce` + `timestamp` window + `intended_recipient` bound inside the signed payload |
| **Limited blast radius** | A leaked token should not grant full coordinator-equivalent capability | Two distinct tokens per keyper: coordinator-scoped vs. peer-scoped (see [Token Scoping](#token-scoping)) |
| **Self-healing on restart** | Neither auto-dkg nor a keyper should need manual re-provisioning after a crash/redeploy | Both sides persist tokens durably — auto-dkg in a hub DB table, each keyper on its own encrypted volume — so a restart reloads instead of re-bootstrapping |

**Core principle applied throughout:** every value crossing a trust boundary answers two separate questions — *"who can read this?"* (confidentiality → encryption) and *"who could have produced this?"* (authenticity → signature). Neither substitutes for the other.

---

## Identities

| Party | Existing identity | New identity added by this design |
|---|---|---|
| Keyper | EIP-191 signing keypair (already used for DKG commitment/share signatures; address is what `te_keyper_addresses` pins) | Dedicated X25519 encryption keypair — **not** the signing key reused; encryption and signing keys must not be shared |
| Coordinator (auto-dkg) | None today | EIP-191 signing keypair (`COORDINATOR_SIGNING_KEY`); its address (`COORDINATOR_ADDRESS`) is pinned as a one-time config value on every keyper |

The `COORDINATOR_ADDRESS` pin and the initial `KEYPER_URLS` list are the only manual, human-driven setup steps left — and both are **non-secret** (an Ethereum address and a set of URLs), so leaking them costs nothing, unlike leaking a bearer token. This is the same low-stakes bootstrap category as today's `KEYPER_URLS`.

**`COORDINATOR_SIGNING_KEY` (auto-dkg) and `COORDINATOR_ADDRESS` (every keyper) must be
deployed together — set both or neither.** A keyper configured with `COORDINATOR_ADDRESS`
(auth required) while auto-dkg is never given `COORDINATOR_SIGNING_KEY` is permanently
locked out: no one could ever produce a signature it will accept, and it fails closed
forever per [step 4a](#4a-pre-bootstrap-state--must-fail-closed-not-open).

---

## Flow

### 1. Keyper publishes its encryption public key, bound to its existing identity

Extend `GET /status` (already unauthenticated by design, per the original doc) with:

```json
{
  "address": "0x...",
  "encryption_pubkey": "<x25519 pubkey, hex>",
  "encryption_pubkey_sig": "<EIP-191 sig over encryption_pubkey, by the keyper's signing key>"
}
```

No secret is exposed here — public keys and signatures are safe to leak. This step needs
integrity only, which the signature already provides; it needs no confidentiality and no
nonce/replay protection (a stale-but-still-valid pubkey announcement is harmless — it's
only ever replaced by an update, never "used up").

### 2. Coordinator discovers and verifies keyper encryption keys

Extends the existing `fetch_members_from_status()` (`dkg_coordinator.py`) — same call that
already learns each keyper's `address` for `te_keyper_addresses` now also reads
`encryption_pubkey` + `encryption_pubkey_sig` and verifies the signature recovers to the
claimed `address` before caching the key. Trust root is the same one already in place:
whoever answers at the configured `KEYPER_URLS` entry is trusted as that keyper (TOFU over
URL) — this design adds no new trust assumption here, it reuses the existing one.

This fetch-and-verify runs once, during auto-dkg's startup bootstrap pass (see
[Rotation, restart recovery](#rotation-restart-recovery)) — the keyper persists its X25519
private key across restarts (`KEYPER_STATE_DIR`, same as the signing key), so
`encryption_pubkey` stays stable and doesn't need re-checking on any recurring schedule.

### 3. Coordinator mints tokens and delivers them sealed + signed

Per keyper `i`, the coordinator generates **two** distinct random tokens (see
[Token Scoping](#token-scoping)) and builds one signed, encrypted envelope carrying
everything keyper `i` needs — its own two tokens, plus a `peers` map giving it, for every
*other* keyper, both **where** to reach it and **what** to authenticate with, from this one
trusted source. DKG endpoints (`round1`, `distribute_commitments`, `distribute_shares`)
carry no auth material *or* destination data at all; this is the only channel:

```python
payload = {
    "intended_recipient": keyper_i_address,
    "api_token": KEYPER_API_TOKEN_i,          # coordinator -> keyper_i auth
    "peer_token": KEYPER_PEER_TOKEN_i,        # other keypers -> keyper_i auth
    "peers": {                                # every OTHER keyper's address + reach info
        "2": {"url": "http://keyper2:5002", "token": KEYPER_PEER_TOKEN_2},
        "3": {"url": "http://keyper3:5003", "token": KEYPER_PEER_TOKEN_3},
    },  # (omits i's own entry; keyed by kid, not address)
    "nonce": secrets.token_hex(16),
    "timestamp": <unix time>,
}
sig = eth_account_sign(payload, COORDINATOR_SIGNING_KEY)   # reuses existing EIP-191 helper
sealed = x25519_seal({"payload": payload, "sig": sig}, keyper_i_encryption_pubkey)
```

`url` and `token` for a given peer travel together in the same map entry rather than as two
parallel structures that happen to share keys — they're always consumed together (to reach
a peer at all, a keyper needs both), and keeping them merged means there's no way for them
to individually drift out of sync.

`x25519_seal` — anonymous sealed box, standard construction, buildable entirely from
`cryptography` (already a pinned dependency, `cryptography>=42,<46`, used today for
`keyper_persistence.py`'s Fernet encryption — no new dependency needed):

```python
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
import os

def x25519_seal(plaintext: bytes, recipient_pubkey: X25519PublicKey) -> bytes:
    eph_priv = X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes_raw()
    shared = eph_priv.exchange(recipient_pubkey)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=eph_pub_bytes + recipient_pubkey.public_bytes_raw()).derive(shared)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return eph_pub_bytes + nonce + ct
```

Note this is **anonymous** encryption (fresh ephemeral keypair per message — anyone can
produce a sealed envelope to a public key). That's fine and expected: authenticity comes
entirely from `sig` inside the plaintext, verified after decryption, not from the
encryption step. Do not mistake "decrypts successfully" for "came from the coordinator" —
decryption only proves the keyper's own private key was used correctly.

Delivered via a new endpoint:

```
POST /auth/bootstrap        (keyper-side, unauthenticated at the HTTP layer —
                              necessarily so, since this call establishes the very
                              bearer token that later calls would check)
Body: <sealed bytes>
```

### 4. Keyper verifies and installs

```python
def handle_bootstrap(sealed_bytes):
    try:
        plaintext = x25519_unseal(sealed_bytes, my_encryption_privkey)
    except Exception:
        return 401  # decrypt/auth-tag failure — reject silently, no detail leaked

    payload, sig = plaintext["payload"], plaintext["sig"]
    signer = eth_account_recover(payload, sig)
    if signer != COORDINATOR_ADDRESS:                        # authenticity
        return 401
    if payload["intended_recipient"] != MY_ADDRESS:           # anti-misdirection
        return 401
    if not fresh(payload["nonce"], payload["timestamp"]):     # anti-replay
        return 401

    install_tokens(api_token=payload["api_token"],
                    peer_token=payload["peer_token"],
                    peers=payload["peers"])
    persist_bootstrap_tokens(...)   # Fernet-encrypted, separate file from dkg_secrets.enc
    return 200
```

`fresh()` checks the timestamp is within a window (e.g. ±5 min) and the nonce hasn't been
seen before, using a short-TTL in-memory set sized to the window — no unbounded growth.

All four checks must pass before any token is installed. On any failure, reject with the
same generic response regardless of which check failed (don't give an attacker an oracle
for which part of their forged envelope was wrong).

**Persisted, not just installed in memory.** All three values (own `api_token`, own
`peer_token`, and `peers`) are written Fernet-encrypted to a second file on the keyper's
volume (`bootstrap_tokens.enc`, alongside but separate from `dkg_secrets.enc`), and loaded
back at startup before the app begins serving. A keyper restart therefore needs **no**
re-bootstrap at all — it resumes exactly where it left off, both for being called and for
calling others. This is what makes dropping the periodic push safe: see
[Rotation, restart recovery](#rotation-restart-recovery).

### 4a. Pre-bootstrap state — must fail closed, not open

A keyper with no persisted `bootstrap_tokens.enc` yet (its very first startup) has no token
installed and stays that way until its first successful `/auth/bootstrap` call lands — which
happens during auto-dkg's one-shot startup pass, so normally within seconds. The original
guard sketch in `keyper-bearer-token-auth.md` treats an empty token as "single-operator dev
mode":

```python
KEYPER_API_TOKEN = os.environ.get("KEYPER_API_TOKEN", "")
@app.before_request
def require_bearer():
    if not KEYPER_API_TOKEN:
        return  # single-operator dev mode
```

That's correct there because the token was static, set once at deploy time — empty meant
the operator deliberately chose no auth. Carried forward unchanged into this design, it's a
bug: `KEYPER_API_TOKEN` is now empty **by default at every startup**, whether or not auth is
supposed to be required, so "not yet bootstrapped" and "dev mode, auth intentionally off"
become indistinguishable and the keyper fails **open** — any endpoint, including `round1`
and `distribute_shares`, is callable by anyone until the coordinator gets around to it.

Fix: separate the static config-time decision ("is auth required at all") from the runtime
state ("has a token actually been installed"), and fail closed on the latter:

```python
AUTH_REQUIRED = bool(os.environ.get("COORDINATOR_ADDRESS", ""))  # set only in multi-operator prod
installed_api_token: str | None = None    # populated by /auth/bootstrap; None until then
installed_peer_token: str | None = None

@app.before_request
def require_bearer():
    if not AUTH_REQUIRED:
        return                                   # explicit single-operator dev mode, unchanged
    if request.path in ("/status", "/auth/bootstrap"):
        return                                   # always reachable — bootstrap has to be
    expected = installed_peer_token if request.path in PEER_ROUTES else installed_api_token
    tok = request.headers.get("Authorization", "")
    if expected is None or not tok.startswith("Bearer ") or \
       not secrets.compare_digest(tok[7:], expected):
        return jsonify({"error": "Unauthorized"}), 401
```

`expected is None` (not yet bootstrapped) must hit the same 401 branch as "wrong token" —
never the early `return` that skips the check. Concretely: hitting any keyper URL before its
first bootstrap succeeds gets `/status` (as designed) and `/auth/bootstrap` (has to be
reachable to end this state) — every other route, including from the real coordinator if it
hasn't reached this keyper yet either, gets a uniform 401.

Two supporting details:
- Keep the 401 identical whether the cause is "no token installed yet" or "wrong token" —
  don't give an unauthenticated prober an oracle for which. If bootstrap state needs to be
  visible for monitoring, add a non-sensitive `"bootstrapped": true/false` field to the
  already-open `/status` — a deliberate, low-risk exposure, not an accidental one via the
  error path.
- Auto-dkg's one-shot bootstrap pass runs immediately on its own startup, before its poll
  loop begins — so the gap is bounded by "however long the later of the two processes takes
  to start," not any recurring interval. A keyper that already has a persisted token from a
  prior bootstrap (the normal case after the first run) has no gap at all: it loads its
  token from disk before serving its first request.

### 5. Acknowledgment — optional, needs new coordinator infra

`auto_dkg.py` is currently a poll loop with no inbound HTTP listener (`auto_dkg.py:246`),
so a keyper→coordinator ack would require standing up a new endpoint just for this. **Not
recommended as a v1 requirement** — instead, treat the next successful authenticated call
in the normal DKG flow (e.g. `round1`) as implicit confirmation that bootstrap succeeded;
log and alert if a keyper keeps 401-ing coordinator calls after a bootstrap push. If an
explicit ack is added later, it needs no encryption (nothing secret to protect — a hash
commitment of the installed token plus a keyper signature is enough), only a way to bind
it to the specific bootstrap round via the shared `nonce`.

---

## Token Scoping

The pre-existing "coordinator-distributed peer tokens" idea used **one** token per keyper
for both purposes — meaning any peer keyper holding another's delivered token for P2P auth
also held that same value's coordinator-level power. A compromised or malicious peer could
therefore call `round1` (ceremony wipe / member hijack, `keyper.py:163`) or
`distribute_shares` (SSRF + secret-share exfiltration, `keyper.py:299`) on another keyper —
not just the low-severity P2P endpoints it was meant to reach. This design mints two
distinct values instead:

| Token | Who holds it | Validates calls to |
|---|---|---|
| `KEYPER_API_TOKEN_i` ("coordinator token") | Auto-dkg, the sequencer, plus keyper `i` itself (to check incoming calls) | `round1`, `round2`, `distribute_commitments`, `distribute_shares`, `publish_on_chain`, `reveal_share`, `decrypt/publish_on_chain` |
| `KEYPER_PEER_TOKEN_i` | Every other keyper `j` (to call keyper `i`), plus keyper `i` itself (to check incoming calls) | `receive_commitments`, `receive_share` |

A leaked/compromised peer token now caps out at flooding another keyper's `receive_*`
routes (medium severity, rate-limitable) instead of triggering a critical-severity flaw.

**Known limitation, accepted by design:** the sequencer authenticates with the same
`KEYPER_API_TOKEN_i` as auto-dkg, not a narrower token — a sequencer compromise therefore
grants the same capability as an auto-dkg compromise (`round1`, `distribute_shares`, etc.),
not just `decrypt/publish_on_chain`. Accepted deliberately to keep the system at two token
types instead of three: auto-dkg and the sequencer are operated by the same party (unlike
keypers, which are cross-organization — the actual reason bearer tokens exist at all), so
this isn't crossing a trust boundary the way a third-party keyper holding it would. Revisit
if the sequencer's attack surface (public ballot ingestion, the largest in this system)
ever becomes a higher priority than the operational simplicity gained here.

---

## Sequencer delivery (via hub DB, plaintext)

The sequencer never talks to the bootstrap channel above — it already reads
`te_keyper_urls`/`te_keyper_addresses` off the `proposals` row per proposal
(`apps/sequencer/src/scores.ts:290`), so the coordinator token rides the same channel
instead of a third distribution mechanism. Auto-dkg writes it into a new column in the same
`UPDATE` that already sets `te_keyper_urls`/`te_keyper_addresses`/`te_config`:

```python
cur.execute(
    """
    UPDATE proposals
       SET te_threshold_t=%s,
           te_threshold_n=%s,
           te_keyper_urls=%s,
           te_keyper_addresses=%s,
           te_config=%s,
           te_keyper_tokens=%s
     WHERE id=%s
    """,
    (
        t, n,
        json.dumps(KEYPER_URLS),
        json.dumps(keyper_addrs),
        json.dumps(te_config),
        json.dumps(keyper_api_tokens),   # KEYPER_API_TOKEN_i, same order as KEYPER_URLS
        pid,
    ),
)
```

`te_keyper_tokens` is stored **plaintext** — a deliberate simplification, not an oversight.
The hub DB is already the trust boundary `te_keyper_addresses`/`te_keyper_urls` live inside;
treating one more column differently would add an encryption key to manage (shared between
auto-dkg and the sequencer) without changing who can already read that row. Revisit if the
hub DB's access model changes (e.g. a read replica or analytics pipeline gets broader
access than the trust this decision assumes).

`apps/sequencer/src/helpers/te.ts` and `scores.ts` read `proposal.te_keyper_tokens[i]`
alongside `proposal.te_keyper_urls[i]` when calling `/decrypt/publish_on_chain`, replacing
the sequencer's own `KEYPER_URLS`/`KEYPER_PEER_TOKENS` env vars (`te.ts:353-358`) entirely.
This also removes the last reason a keyper-side token change would require a sequencer
restart — the sequencer now reads the current token fresh on every tally tick instead of
once at process boot.

**Written once; resynced only when a rotation actually happens.** `_ensure_dkg()` writes
`te_keyper_tokens` when DKG starts, and — since tokens don't rotate automatically anymore
(see [Rotation, restart recovery](#rotation-restart-recovery)) — that value simply stays
valid for the proposal's whole lifetime. The only time it can go stale is a deliberate
forced rotation (an operator clears a keyper's row via `scripts/rotate_keyper_token.py`) or
a new keyper joining the fleet; `_bootstrap_keypers_once()` calls
`_resync_open_proposal_tokens()` in that case only.

That resync is **per-proposal-aware**, not a single blanket `UPDATE`: it reads each open
proposal's own `te_keyper_urls` and rebuilds that row's token array via an `API_TOKENS`
dict lookup keyed by URL, rather than assuming the process's current `KEYPER_URLS` list
applies uniformly to every row. A proposal's `te_keyper_urls` is frozen at its own
DKG-start time — if the committee's membership or order ever changed since (an operator
added/removed/reordered a keyper) while that proposal was still open, writing one shared
array built from the *current* `KEYPER_URLS` would silently misalign that older proposal's
tokens against its own URLs, sending the wrong token to the wrong keyper for that specific
proposal. Still bounded by concurrently-active private proposals rather than total
historical proposal count, since a row permanently drops out of the resync set once
`scores_state='final'`. There's a narrow, self-healing race on the rare occasion a rotation
happens (the DB write and the keyper bootstrap push aren't atomic across processes) where a
tally tick could hit a keyper mid-rotation — `triggerKeypers` already swallows fetch errors
and the next tally tick retries, so this costs at most one missed tick, not a stuck state.

---

## Rotation, restart recovery

**No automatic rotation.** Earlier drafts of this design re-minted every token on a timer
(`TOKEN_PUSH_INTERVAL_S`), and the sole reason was restart recovery — the coordinator had no
way to learn that an independently operated keyper had restarted and lost its installed
tokens, so it kept re-pushing everyone, indefinitely. That turned out to be the wrong tool
for the job: rotating tokens the sequencer had already cached in `te_keyper_tokens` (written
once, at DKG start) required an ongoing resync just to avoid breaking the decrypt path for
any proposal open longer than one rotation interval — real complexity purchased almost
entirely to solve a restart-recovery problem that persistence solves more directly.

**Both sides persist tokens durably instead:**

- **Keyper** — its own `api_token`, `peer_token`, and outbound `peers` map (`{kid: {url,
  token}}` for every other keyper) are Fernet-encrypted to `bootstrap_tokens.enc` on its
  volume (step 4), separate from `dkg_secrets.enc`, and loaded back at startup before the
  app serves requests. A keyper restart needs **no** re-bootstrap — it resumes immediately,
  both for being called and for calling others.
- **Auto-dkg** — a new hub DB table, `keyper_bootstrap_tokens` (one row per keyper URL,
  `api_token`/`peer_token`, plaintext — same trust-boundary reasoning as
  `proposals.te_keyper_tokens`), is its durable record. An auto-dkg restart loads existing
  tokens from this table instead of re-minting the whole fleet.

**Bootstrap becomes a one-shot pass, run once before `run_forever()`'s poll loop starts**
(`_bootstrap_keypers_once()` in `auto_dkg.py`), not a recurring tick:

1. Load `keyper_bootstrap_tokens`. For any keyper URL with **no row** (a new keyper, or one
   whose row was deliberately deleted — see below), mint a fresh `(api_token, peer_token)`
   pair.
2. If **any** keyper needed a fresh mint, re-push a full bootstrap payload to **every**
   keyper, not just the new one — every keyper's `peers` map depends on the complete current
   set, so a change to one keyper's `peer_token` has to reach everyone else's map too.
   Unaffected keypers just get their own unchanged values reinstalled alongside the one
   updated entry.
3. If **nothing** was missing, check each keyper's live `/status.bootstrapped` flag instead
   (`fetch_bootstrapped_status()`, `dkg_coordinator.py`) — a keyper reporting `false` despite
   having a DB row means it lost its own persisted file (e.g. a wiped volume, not a normal
   restart); re-push *only* to that keyper, with its unchanged, already-recorded values. No
   value changed anywhere, so nothing ripples.
4. If every keyper already has a row and reports `bootstrapped=true`, do nothing at all.
5. Persist any freshly minted rows, and run `_resync_open_proposal_tokens()` — but only if
   step 1 found something missing (see "Sequencer delivery").

Because this whole pass runs once, before the poll loop begins, it can never race an
in-flight DKG ceremony — there's no ceremony to race yet. That sidesteps the "must never run
on a separate thread" constraint the timer-based version needed.

**Forcing a rotation deliberately** (suspected leak, decommissioning an operator, routine
hygiene) reuses the exact same mechanism: delete the target keyper's row —

```
python3 scripts/rotate_keyper_token.py --keyper-url http://keyper2:5002   # or --all
docker compose restart auto-dkg
```

— and the next startup pass treats the missing row exactly like a brand-new keyper joining:
mints a fresh value, ripples the updated `peers` map to the whole fleet, and resyncs
`te_keyper_tokens` for any still-open proposal. No new endpoint, no new trigger channel —
deleting a row and restarting is the entire mechanism.

**Accepted tradeoff:** a push that fails (keyper unreachable during the startup pass) isn't
retried until the next auto-dkg restart, since there's no periodic timer anymore. The
intended token is still persisted to `keyper_bootstrap_tokens` regardless of push success,
so the next restart's reconciliation (step 3 above) will find the row present,
`bootstrapped=false`, and retry with the same value — but "the next restart" could be a
while. This trades a small, rare availability gap for removing a continuously running
resync mechanism; revisit if that gap proves to matter in practice.

---

## Hardening carried over from earlier threat analysis (unchanged, still required)

These apply regardless of how tokens are delivered:

- **TLS mandatory, properly validated** — reject plaintext fallback; validate the server
  certificate identity before ever POSTing (this design's encryption removes reliance on
  TLS for *token* confidentiality specifically, but TLS still matters for integrity,
  availability, and everything else on the wire).
- **No caller-supplied destinations in `distribute_shares`/`distribute_commitments` at
  all** — an earlier revision of this design had the coordinator pass a `keyper_urls` map
  in the request body, checked against a value `round1` had pinned earlier in the same
  ceremony. That doesn't actually survive the threat it claims to: whoever holds a leaked
  `api_token` can call `round1` too, which resets the pin to anything they want, then match
  it at `distribute_shares` — the same token unlocks both the data and the check on that
  data. The fix isn't a stronger check, it's removing the caller-supplied input entirely:
  `distribute_commitments`/`distribute_shares` now fan out to the keyper's own
  bootstrap-installed `peers` map (see step 3) and accept no destination data in the request
  body at all. This neutralizes the SSRF/exfiltration flaw even under a full `api_token`
  compromise, since redirecting a share now requires forging a new signed bootstrap
  envelope — the coordinator's actual private key, not just the bearer token.
- **Complaint-existence guard on `reveal_share`** (`keyper.py:375`) — don't return a
  plaintext share without checking a complaint was actually filed for that recipient.
- **Rate limiting per route**, at the proxy — a valid-but-leaked token still shouldn't be
  able to flood. This matters most for `/status` and `/auth/bootstrap` specifically: both
  are unauthenticated by necessity (bootstrap has to be reachable before any token exists;
  `/status` is the health probe), so for these two routes rate limiting is the *only*
  defense layer, not a second one behind a bearer check — intentional, not an oversight.
- **Redact `/auth/bootstrap` request/response bodies from all logs** — the sealed envelope
  is opaque ciphertext so logging it is low-risk, but avoid logging the decrypted plaintext
  on the keyper side (log success/failure + signer address only).

---

## Files to modify

| File | Change |
|---|---|
| `src/keyper_persistence.py` (renamed from `dkg_persistence.py` — now covers more than DKG secrets) | Add `load_or_create_encryption_key` (X25519 keypair persistence); add `save_bootstrap_tokens`/`load_bootstrap_tokens` (own api_token/peer_token/peers map, Fernet-encrypted to `bootstrap_tokens.enc`, separate from `dkg_secrets.enc`) |
| `src/token_bootstrap.py` (new) | Shared X25519 sealed-box helpers, EIP-191 payload hashing, nonce/replay tracking — used by both `keyper.py` and `dkg_coordinator.py` |
| `src/keyper.py` | Load persisted tokens at startup; extend `/status` with `encryption_pubkey` + signature + `bootstrapped` flag; add `POST /auth/bootstrap` (decrypt, verify, install `peers`, persist); fail-closed `before_request` guard split by route (api/peer/dual); `round1`/`distribute_commitments`/`distribute_shares` carry no auth material or destination data at all — fan-out uses the installed `peers` map exclusively |
| `src/dkg_coordinator.py` | `fetch_encryption_pubkeys()`, `fetch_bootstrapped_status()`, `push_bootstrap()` (payload now includes the merged `peers` map); `run_dkg()` takes `api_tokens` only and sends no `keyper_urls`/peer data to any DKG endpoint; `build_keyper_urls_map()` removed (no longer used anywhere) |
| `src/auto_dkg.py` | Add `COORDINATOR_SIGNING_KEY`; `_load_persisted_tokens`/`_save_persisted_token` against the new table; `_bootstrap_keypers_once()` — the reconciliation pass described above, called once before `run_forever()`'s loop, not on a timer; write `te_keyper_tokens` in `_ensure_dkg()`'s `UPDATE proposals` call |
| `scripts/rotate_keyper_token.py` (new) | Operator helper — deletes a keyper's (or every keyper's) row from `keyper_bootstrap_tokens` to force a rotation on the next auto-dkg restart |
| `apps/hub/src/helpers/schema.sql` | Add `te_keyper_tokens` (JSON, plaintext) to `proposals`; add new `keyper_bootstrap_tokens` table (plaintext, one row per keyper URL) |
| `docker-compose.yml` / `docker-compose.hub.yml` / `docker-compose.keyper.yml` | Add `COORDINATOR_SIGNING_KEY` (auto-dkg), `COORDINATOR_ADDRESS` (each keyper); no `TOKEN_PUSH_INTERVAL_S` |
| `.env.hub.example` / `.env.keyper.example` | Document new env vars; remove old manual token-sharing instructions |
| `apps/sequencer/src/helpers/te.ts` | Delete the `KEYPER_URLS`/`KEYPER_PEER_TOKENS` env-var token map; read the token from `proposal.te_keyper_tokens[i]` per call instead |
| `apps/sequencer/src/scores.ts` | Parse `te_keyper_tokens`, pass through to `triggerKeypers()` alongside `te_keyper_urls` |
| `docs/private-voting/keyper-bearer-token-auth.md` | Mark "Token Management" / "Coordinator-Distributed Peer Tokens" sections as superseded by this doc |
