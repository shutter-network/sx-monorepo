#!/usr/bin/env python3
"""Force a keyper bearer-token rotation by clearing its persisted record.

Tokens are minted once and never rotate automatically (see
docs/private-voting/keyper-token-bootstrap.md) -- both auto-dkg and each
keyper persist them durably. To deliberately rotate one or more keypers
(suspected leak, routine hygiene, decommissioning an operator), delete the
relevant row(s) from ``keyper_bootstrap_tokens`` and restart auto-dkg: its
startup reconciliation pass treats a missing row exactly like a brand-new
keyper joining -- mints a fresh token, pushes it via /auth/bootstrap, and
(since every other keyper's outbound ``peers`` map depends on the full set)
re-pushes the current values to the rest of the fleet too.

This script only clears the row; it does NOT restart auto-dkg for you --
run it, then restart the auto-dkg service yourself. scripts/ isn't copied into
the container image (only src/ is), so run this on the hub operator's machine
against the mysql container's published port rather than inside auto-dkg:

    HUB_DB_HOST=127.0.0.1 HUB_DB_PORT=3306 python3 \\
        services/keypers/scripts/rotate_keyper_token.py --keyper-url http://host.docker.internal:5001
    docker compose -f docker-compose.hub.yml restart auto-dkg

Rotate the whole fleet with --all instead of --keyper-url.

Reads the same HUB_DB_* environment variables as auto_dkg.py.
"""
from __future__ import annotations

import argparse
import os

import pymysql


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


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--keyper-url", help="Base URL of the one keyper to rotate (e.g. http://keyper2:5002)")
    group.add_argument("--all", action="store_true", help="Rotate every keyper's token")
    args = p.parse_args()

    conn = _db_connect()
    try:
        with conn.cursor() as cur:
            if args.all:
                cur.execute("DELETE FROM keyper_bootstrap_tokens")
                print(f"Cleared {cur.rowcount} row(s) -- restart auto-dkg to re-bootstrap the whole fleet.")
            else:
                url = args.keyper_url.rstrip("/")
                cur.execute("DELETE FROM keyper_bootstrap_tokens WHERE keyper_url=%s", (url,))
                if cur.rowcount == 0:
                    print(f"No row found for {url} -- nothing to rotate (already unbootstrapped, or wrong URL).")
                else:
                    print(f"Cleared token for {url} -- restart auto-dkg to force a fresh mint.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
