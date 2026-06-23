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
  KEYPER_PRIVATE_KEYS  Comma-separated keyper signing keys, in keyper-id order.
                       Used only to derive the te_keyper_addresses allow-list so
                       the hub accepts each keyper's DKG submission. REQUIRED —
                       the coordinator exits with an error if this is not set.
  TE_THRESHOLD_T       Threshold degree t (need t+1 shares). Default: 1.
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
import time

import pymysql
from eth_account import Account

from dkg_coordinator import run_dkg  # vendored in this image at /app/src

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [auto-dkg] %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
)
log = logging.getLogger('auto-dkg')

POLL_INTERVAL_S = float(os.environ.get("POLL_INTERVAL_S", "2"))
MAX_FAILURES = 5
DEFAULT_T = int(os.environ.get("TE_THRESHOLD_T", "1"))
DEFAULT_BUDGET = 1
DEFAULT_MODE = "exact"


def _keyper_urls() -> list[str]:
    raw = os.environ.get(
        "KEYPER_URLS",
        "http://keyper1:5001,http://keyper2:5002,http://keyper3:5003",
    )
    return [u.strip().rstrip("/") for u in raw.split(",") if u.strip()]


def _keyper_addresses(n: int) -> list[str]:
    raw = os.environ.get("KEYPER_PRIVATE_KEYS", "").strip()
    if not raw:
        raise SystemExit(
            "Error: KEYPER_PRIVATE_KEYS is required.\n"
            "Set it to a comma-separated list of the keyper signing keys (0x-prefixed) "
            "in keyper-id order, matching KEYPER_PRIVATE_KEY_{1,2,3} in .env."
        )
    keys = [k.strip() for k in raw.split(",") if k.strip()]
    if len(keys) != n:
        raise SystemExit(
            f"KEYPER_PRIVATE_KEYS has {len(keys)} keys but KEYPER_URLS has {n} urls"
        )
    return [Account.from_key(k).address for k in keys]


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
KEYPER_ADDRS = _keyper_addresses(len(KEYPER_URLS))


def _ensure_dkg(pid: str, choices: list) -> bool:
    """Populate te_* config and run DKG for one proposal. Returns True on success."""
    n = len(KEYPER_URLS)
    t = DEFAULT_T
    num_candidates = len(choices)
    te_config = {
        "numCandidates": num_candidates,
        "budget": DEFAULT_BUDGET,
        "mode": DEFAULT_MODE,
        "variant": "A",
    }

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
                       te_config=%s
                 WHERE id=%s
                """,
                (
                    t, n,
                    json.dumps(KEYPER_URLS),
                    json.dumps(KEYPER_ADDRS),
                    json.dumps(te_config),
                    pid,
                ),
            )
    finally:
        conn.close()

    log.info("op=dkg_start proposal=%s n=%d t=%d candidates=%d", pid, n, t, num_candidates)
    run_dkg(
        keyper_urls=KEYPER_URLS,
        election_id=pid,
        election_address=pid,
        n=n, t=t,
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
    failures: dict[str, int] = {}
    while True:
        try:
            conn = _db_connect()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT id, choices FROM proposals "
                        "WHERE privacy='shutter-elgamal' AND te_mpk IS NULL"
                    )
                    rows = cur.fetchall()
            finally:
                conn.close()
            for pid, choices_json in rows:
                if failures.get(pid, 0) >= MAX_FAILURES:
                    continue
                choices = (
                    json.loads(choices_json)
                    if isinstance(choices_json, str)
                    else choices_json
                )
                try:
                    ok = _ensure_dkg(pid, choices)
                    if not ok:
                        failures[pid] = failures.get(pid, 0) + 1
                except Exception as e:  # noqa: BLE001
                    failures[pid] = failures.get(pid, 0) + 1
                    log.error("op=dkg_start proposal=%s status=error attempt=%d/%d err=%s",
                              pid, failures[pid], MAX_FAILURES, e)
        except Exception as e:  # noqa: BLE001
            log.error("poll_error err=%s", e)
        time.sleep(poll_interval_s)

if __name__ == "__main__":
    try:
        run_forever()
    except KeyboardInterrupt:
        log.info("stopped")
