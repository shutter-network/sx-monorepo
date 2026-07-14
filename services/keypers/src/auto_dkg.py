#!/usr/bin/env python3
"""Container-aware auto-DKG coordinator.

Polls the hub database for permanent-private (``privacy='shutter-elgamal'``)
proposals whose threshold key has not been generated yet (``te_mpk IS NULL``)
and drives the distributed key generation ceremony against the keyper
committee automatically. As soon as a proposal is created, the committee
derives the master public key within a couple of seconds so the UI can start
encrypting ballots.

This is the dockerised counterpart of ``scripts/auto_dkg.py``: instead of the
hard-coded ``localhost`` endpoints used for host-run dev, every endpoint is
read from the environment so it works inside a compose network.

Environment:
  KEYPER_URLS          Comma-separated keyper base URLs.
                       Default: http://keyper1:5001,http://keyper2:5002,http://keyper3:5003
  COORDINATOR_SIGNING_KEY  This coordinator's own EIP-191 signing key, used to
                       authenticate the token-bootstrap payload to keypers.
                       Empty = single-operator dev mode, no bootstrap runs.
  TE_THRESHOLD_T       Threshold degree t (need t+1 shares). Default: 1.
  TE_WEIGHTED_BUDGET   Denominator for weighted vote splits (e.g. 100 = percentages,
                       1000 = 0.1% granularity). Default: 100.
  POLL_INTERVAL_S      Seconds between DB polls. Default: 2.
  HUB_DB_HOST          MySQL host. Default: mysql
  HUB_DB_PORT          MySQL port. Default: 3306
  HUB_DB_USER          MySQL user. Default: root
  HUB_DB_PASSWORD      MySQL password. Default: "" (empty)
  HUB_DB_NAME          Hub database name. Default: snapshot_hub
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import time

import pymysql

from dkg_coordinator import (  # vendored in this image at /app/src
    run_dkg,
    fetch_members_from_status,
    fetch_encryption_pubkeys,
    fetch_bootstrapped_status,
    push_bootstrap,
    _keypers_from_urls,
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [auto-dkg] %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
)
log = logging.getLogger('auto-dkg')

POLL_INTERVAL_S = float(os.environ.get("POLL_INTERVAL_S", "2"))
# Retry budget and exponential backoff parameters.
MAX_ATTEMPTS = 5
BACKOFF_BASE_S = 10        # minimum delay between retries (floor)
BACKOFF_CAP_S = 500        # maximum single delay (cap)
LAST_ATTEMPT_MARGIN_S = 10 # fire the final retry at least this many seconds before start
DEFAULT_T = int(os.environ.get("TE_THRESHOLD_T", "1"))
DEFAULT_BUDGET = 1
WEIGHTED_BUDGET = int(os.environ.get("TE_WEIGHTED_BUDGET", "100"))
DEFAULT_MODE = "exact"


def _keyper_urls() -> list[str]:
    raw = os.environ.get(
        "KEYPER_URLS",
        "http://keyper1:5001,http://keyper2:5002,http://keyper3:5003",
    )
    return [u.strip().rstrip("/") for u in raw.split(",") if u.strip()]



def _db_connect():
    return pymysql.connect(
        host=os.environ.get("HUB_DB_HOST", "mysql"),
        port=int(os.environ.get("HUB_DB_PORT", "3306")),
        user=os.environ.get("HUB_DB_USER", "root"),
        password=os.environ.get("HUB_DB_PASSWORD", ""),
        database=os.environ.get("HUB_DB_NAME", "snapshot_hub"),
        charset="utf8mb4",
        autocommit=True,
    )


KEYPER_URLS = _keyper_urls()

# Coordinator's own EIP-191 signing key, used to authenticate the token
# bootstrap payload to keypers (verified there against each keyper's pinned
# COORDINATOR_ADDRESS). Empty = single-operator dev mode, no bootstrap runs.
COORDINATOR_SIGNING_KEY = os.environ.get("COORDINATOR_SIGNING_KEY", "")

# Coordinator/API token per keyper, url -> token. Populated once by
# _bootstrap_keypers_once() at startup, from the durable keyper_bootstrap_tokens
# table (falling back to a fresh mint for any keyper with no row yet). No
# rotation -- tokens are minted once and persisted on both sides (this
# table, and each keyper's own encrypted volume). Empty in single-operator
# mode. See docs/private-voting/keyper-token-bootstrap.md.
API_TOKENS: dict[str, str] = {}


def _load_persisted_tokens(conn) -> dict[str, dict[str, str]]:
    """{url: {api_token, peer_token}} from keyper_bootstrap_tokens -- this
    is auto-dkg's own durable record, so its restart doesn't force a
    fleet-wide re-mint the way losing an in-memory-only map would."""
    with conn.cursor() as cur:
        cur.execute("SELECT keyper_url, api_token, peer_token FROM keyper_bootstrap_tokens")
        return {
            url: {"api_token": api_tok, "peer_token": peer_tok}
            for url, api_tok, peer_tok in cur.fetchall()
        }


def _save_persisted_token(conn, url: str, api_token: str, peer_token: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO keyper_bootstrap_tokens (keyper_url, api_token, peer_token, updated)
            VALUES (%s, %s, %s, UNIX_TIMESTAMP())
            ON DUPLICATE KEY UPDATE api_token=VALUES(api_token),
                                     peer_token=VALUES(peer_token),
                                     updated=VALUES(updated)
            """,
            (url, api_token, peer_token),
        )


def _resync_open_proposal_tokens() -> None:
    """Rewrite te_keyper_tokens for every proposal whose DKG has completed
    but whose tally isn't final yet.

    Only called when a rotation actually happened this pass (a keyper's row
    was missing -- a new keyper, or one deliberately reset to force a
    rotation, see scripts/rotate_keyper_token.py). Without this, an
    already-DKG-completed proposal would keep a token its keypers no longer
    recognize. Scoped to "DKG done, not yet finalized" so it stays bounded
    by concurrently-active private proposals -- a row drops out of this set
    permanently once scores_state='final'.

    Rebuilds each row's token array from *that row's own* te_keyper_urls via
    an API_TOKENS dict lookup (by URL), rather than assuming the process's
    current KEYPER_URLS list applies to every open proposal. A proposal's
    te_keyper_urls is frozen at its own DKG-start time; if the committee's
    membership or order ever changed since (an operator added/removed/
    reordered a keyper) while that proposal was still open, writing a
    single shared array built from the *current* KEYPER_URLS would silently
    misalign that older proposal's tokens against its own URLs.
    """
    conn = _db_connect()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, te_keyper_urls FROM proposals
                 WHERE te_mpk IS NOT NULL
                   AND (scores_state IS NULL OR scores_state != 'final')
                """
            )
            rows = cur.fetchall()
            n = 0
            for pid, keyper_urls_json in rows:
                urls = (
                    json.loads(keyper_urls_json)
                    if isinstance(keyper_urls_json, str)
                    else keyper_urls_json
                )
                tokens_ordered = json.dumps([API_TOKENS.get(u.rstrip("/"), "") for u in urls])
                cur.execute(
                    "UPDATE proposals SET te_keyper_tokens=%s WHERE id=%s",
                    (tokens_ordered, pid),
                )
                n += 1
            log.info("op=resync_open_proposal_tokens status=ok rows=%d", n)
    finally:
        conn.close()


def _bootstrap_keypers_once() -> None:
    """One-time token bootstrap pass, run before the poll loop starts.

    No periodic rotation -- tokens are minted once and persisted on both
    sides. This pass only touches keypers that actually need something:

    - A keyper with no row in keyper_bootstrap_tokens (a new keyper, or one
      whose row was deliberately deleted to force a rotation) gets a fresh
      mint. Every other keyper's own peers map depends on this
      keyper's current peer_token, so a fresh mint ripples: every keyper
      gets re-pushed a full bootstrap payload, not just the one that
      changed (the unaffected ones just get their own unchanged values
      reinstalled, plus an updated entry for the one that rotated).
    - A keyper whose row IS present but whose live /status.bootstrapped
      reports False (it lost its own persisted file) gets a targeted
      re-push of its unchanged, already-recorded values -- nothing else is
      touched, since no value actually changed anywhere.
    - A keyper that's healthy with a row already present is left alone.

    A failed push (unreachable keyper) still gets its intended token
    persisted here -- the next auto-dkg restart's reconciliation will see
    its row present but bootstrapped=False and retry with the same value.
    There's no periodic retry anymore, so a transient failure during this
    pass isn't auto-corrected until the next restart; that's an accepted
    tradeoff of dropping the timer. See "Rotation, restart recovery" in
    keyper-token-bootstrap.md.
    """
    if not COORDINATOR_SIGNING_KEY:
        return
    try:
        keypers = _keypers_from_urls(KEYPER_URLS)
        member_addrs = fetch_members_from_status(keypers)

        conn = _db_connect()
        try:
            existing = _load_persisted_tokens(conn)
        finally:
            conn.close()

        urls = [kp.url.rstrip("/") for kp in keypers]
        missing_urls = [u for u in urls if u not in existing]

        tokens_by_url = dict(existing)
        for url in missing_urls:
            tokens_by_url[url] = {
                "api_token": secrets.token_hex(32),
                "peer_token": secrets.token_hex(32),
            }
        for url, toks in tokens_by_url.items():
            API_TOKENS[url] = toks["api_token"]

        if missing_urls:
            # A value changed -- every keyper's peers map
            # depends on the full set, so re-push to everyone.
            target_kids = {kp.kid for kp in keypers}
        else:
            bootstrapped = fetch_bootstrapped_status(keypers)
            target_kids = {kp.kid for kp in keypers if not bootstrapped.get(kp.kid, True)}

        if not target_kids:
            log.info("op=bootstrap_keypers status=ok action=none")
            return

        enc_pubkeys = fetch_encryption_pubkeys(keypers, member_addrs)
        pushed = 0
        for kp, addr in zip(keypers, member_addrs):
            if kp.kid not in target_kids:
                continue
            enc_pubkey = enc_pubkeys.get(kp.kid)
            if enc_pubkey is None:
                continue
            url = kp.url.rstrip("/")
            own = tokens_by_url[url]
            # {kid: {"url", "token"}} for every *other* keyper -- both where
            # to reach it and what to authenticate with, so DKG endpoints
            # never need keyper_urls in their own request body at all.
            peers = {
                str(other.kid): {
                    "url": other.url,
                    "token": tokens_by_url[other.url.rstrip("/")]["peer_token"],
                }
                for other in keypers if other.kid != kp.kid
            }
            ok = push_bootstrap(kp, addr, own["api_token"], own["peer_token"],
                                 peers, enc_pubkey, COORDINATOR_SIGNING_KEY)
            if ok:
                pushed += 1

        if missing_urls:
            conn = _db_connect()
            try:
                for url in missing_urls:
                    _save_persisted_token(conn, url, tokens_by_url[url]["api_token"],
                                           tokens_by_url[url]["peer_token"])
            finally:
                conn.close()
            _resync_open_proposal_tokens()

        log.info("op=bootstrap_keypers status=ok pushed=%d/%d new=%d",
                  pushed, len(target_kids), len(missing_urls))
    except Exception as e:  # noqa: BLE001
        log.error("op=bootstrap_keypers status=error err=%s", e)


def _mark_dkg_failed(pid: str) -> None:
    """Write te_dkg_status='dkg_failed' so the poll query stops retrying."""
    conn = _db_connect()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE proposals SET te_dkg_status='dkg_failed' WHERE id=%s",
                (pid,)
            )
    finally:
        conn.close()


def _on_failure(
    pid: str,
    reason: str,
    proposal_start: int,
    attempt_count: dict[str, int],
    next_retry_at: dict[str, float],
) -> None:
    """Record a DKG attempt failure. Backoff is proportional to the remaining
    time before the proposal opens: retries are spaced evenly within that window
    so the most urgent proposals always get the fastest retries. Marks the
    proposal permanently failed in the DB after MAX_ATTEMPTS."""
    attempt = attempt_count.get(pid, 0) + 1
    attempt_count[pid] = attempt

    if attempt >= MAX_ATTEMPTS:
        log.error(
            "op=dkg_permanently_failed proposal=%s attempts=%d reason=%s "
            "-- set te_dkg_status=NULL in the DB to retry",
            pid, attempt, reason,
        )
        _mark_dkg_failed(pid)
        attempt_count.pop(pid, None)
        next_retry_at.pop(pid, None)
    else:
        remaining_attempts = MAX_ATTEMPTS - attempt
        time_until_start = max(0.0, proposal_start - time.time())
        # Exponential geometric series: delays double each attempt and sum to
        # exactly the usable budget (time left minus the last-attempt margin).
        # d + 2d + 4d + ... + 2^(n-1)d = d * (2^n - 1) = budget
        # => d = budget / (2^n - 1)
        budget = max(0.0, time_until_start - LAST_ATTEMPT_MARGIN_S)
        slots = (2 ** remaining_attempts) - 1
        delay = min(
            max(float(BACKOFF_BASE_S), budget / slots),
            float(BACKOFF_CAP_S),
        )
        next_retry_at[pid] = time.time() + delay
        log.warning(
            "op=dkg_retry proposal=%s attempt=%d/%d delay_s=%.0f "
            "time_until_start=%.0f reason=%s",
            pid, attempt, MAX_ATTEMPTS, delay, time_until_start, reason,
        )


def _ensure_dkg(pid: str, choices: list, vote_type: str, end_time: int) -> bool:
    """Populate te_* config and run DKG for one proposal. Returns True on success."""
    n = len(KEYPER_URLS)
    t = DEFAULT_T
    keypers = _keypers_from_urls(KEYPER_URLS)
    keyper_addrs = fetch_members_from_status(keypers)
    num_candidates = len(choices)
    # Weighted proposals encode proportional splits as integers out of WEIGHTED_BUDGET
    # (e.g. 60+40=100); the tally path divides recovered sums by budget at the end.
    budget = WEIGHTED_BUDGET if vote_type == "weighted" else DEFAULT_BUDGET
    te_config = {
        "numCandidates": num_candidates,
        "budget": budget,
        "mode": DEFAULT_MODE,
        "variant": "A",
    }

    # Coordinator/API token per keyper (same order as KEYPER_URLS), plaintext
    # -- the sequencer reads this alongside te_keyper_urls to call
    # /decrypt/publish_on_chain. Deliberately plaintext and deliberately the
    # same token auto-dkg itself uses (not a narrower one) -- see "Token
    # Scoping" / "Sequencer delivery" in keyper-token-bootstrap.md.
    keyper_tokens_ordered = [API_TOKENS.get(u.rstrip("/"), "") for u in KEYPER_URLS]

    conn = _db_connect()
    try:
        with conn.cursor() as cur:
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
                    json.dumps(keyper_tokens_ordered),
                    pid,
                ),
            )
    finally:
        conn.close()

    log.info("op=dkg_start proposal=%s n=%d t=%d candidates=%d budget=%d vote_type=%s",
             pid, n, t, num_candidates, budget, vote_type)
    run_dkg(
        keyper_urls=KEYPER_URLS,
        election_id=pid,
        election_address=pid,
        n=n, t=t,
        members=keyper_addrs,
        api_tokens=API_TOKENS,
        proposal_end_time=end_time,
    )

    deadline = time.time() + 30
    while time.time() < deadline:
        conn = _db_connect()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT HEX(te_mpk) FROM proposals WHERE id=%s", (pid,))
                row = cur.fetchone()
        finally:
            conn.close()
        if row and row[0]:
            log.info("op=dkg_complete proposal=%s status=ok", pid)
            return True
        time.sleep(0.5)

    log.error("op=dkg_complete proposal=%s status=timeout", pid)
    return False


def run_forever(poll_interval_s: float = POLL_INTERVAL_S) -> None:
    log.info("coordinator started poll_interval=%.1fs keypers=%s t=%d",
             poll_interval_s, KEYPER_URLS, DEFAULT_T)

    # Per-proposal retry state (in-memory; resets on restart, which is fine
    # since a restart is an intentional operator action that clears backoff).
    attempt_count: dict[str, int] = {}
    next_retry_at: dict[str, float] = {}

    # One-shot, before the poll loop starts -- no periodic rotation. Since
    # this runs before any DKG activity begins, it can't race an in-flight
    # ceremony the way a periodic push from a separate thread could.
    _bootstrap_keypers_once()

    while True:
        try:
            conn = _db_connect()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT id, choices, type, end, start FROM proposals "
                        "WHERE privacy='shutter-elgamal' AND te_mpk IS NULL "
                        "AND (te_dkg_status IS NULL OR te_dkg_status = '') "
                        "ORDER BY start ASC"
                    )
                    rows = cur.fetchall()
            finally:
                conn.close()
            for pid, choices_json, vote_type, end_time, start_time in rows:
                # skip until backoff window expires.
                if time.time() < next_retry_at.get(pid, 0):
                    continue
                choices = (
                    json.loads(choices_json)
                    if isinstance(choices_json, str)
                    else choices_json
                )
                try:
                    ok = _ensure_dkg(pid, choices, vote_type or "single-choice", end_time)
                    if ok:
                        attempt_count.pop(pid, None)
                        next_retry_at.pop(pid, None)
                    else:
                        _on_failure(pid, "timeout", start_time, attempt_count, next_retry_at)
                except Exception as e:  # noqa: BLE001
                    _on_failure(pid, str(e), start_time, attempt_count, next_retry_at)
        except Exception as e:  # noqa: BLE001
            log.error("poll_error err=%s", e)
        time.sleep(poll_interval_s)

if __name__ == "__main__":
    try:
        run_forever()
    except KeyboardInterrupt:
        log.info("stopped")
