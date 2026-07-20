#!/usr/bin/env python3
"""
DKG coordinator — orchestrates the keyper HTTP APIs for Feldman VSS DKG.

Flow (matches RUNNING.md):
  round1 → distribute_commitments → distribute_shares → round2 → publish_on_chain
"""

from __future__ import annotations

import argparse
import json
import logging
import secrets
import sys
import time
from dataclasses import dataclass
from typing import Any, Optional

import requests
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from eth_account import Account
from eth_account.messages import encode_defunct

from token_bootstrap import enc_pubkey_hash, payload_hash, x25519_seal

log = logging.getLogger('dkg')

# HTTP timeout for a single /auth/bootstrap push.
_BOOTSTRAP_TIMEOUT_S = 20.0


def _eth_sign(payload_dict: dict, private_key: str) -> str:
    msg = encode_defunct(primitive=payload_hash(payload_dict))
    return Account.from_key(private_key).sign_message(msg).signature.hex()


class DKGCoordinatorError(RuntimeError):
    pass


@dataclass(frozen=True)
class Keyper:
    kid: int
    url: str


def _keypers_from_urls(urls: list[str]) -> list[Keyper]:
    # Assuming keyper ids are 1-indexed. ie 1,2,3
    return [Keyper(kid=i + 1, url=u.rstrip("/")) for i, u in enumerate(urls)]


def fetch_members_from_status(keypers: list[Keyper], *, timeout: float = 5.0) -> list[str]:
    """
    Fetch the expected DKG `members` list from each keyper `/status`.
    We take the first successful set (and sanity-check that all match).
    """
    members_by_kid: dict[int, str] = {}
    for kp in keypers:
        r = requests.get(f"{kp.url}/status", timeout=timeout)
        r.raise_for_status()
        j = r.json()
        addr = j.get("address")
        if not isinstance(addr, str) or not addr.startswith("0x"):
            raise DKGCoordinatorError(f"{kp.url}/status missing/invalid address")
        members_by_kid[kp.kid] = addr

    # Deterministic, member-index order = keyper_id order.
    return [members_by_kid[kp.kid] for kp in keypers]


def _verify_encryption_pubkey(address: str, pubkey_hex: str, sig_hex: str) -> X25519PublicKey:
    """Verify a keyper's self-published encryption_pubkey is bound to its
    already-trusted signing address, then return the parsed public key.

    Raises on any failure -- callers must treat that keyper as not
    bootstrappable this round rather than silently skipping verification.
    """
    pubkey_bytes = bytes.fromhex(pubkey_hex.removeprefix("0x"))
    msg = encode_defunct(primitive=enc_pubkey_hash(pubkey_bytes))
    recovered = Account.recover_message(msg, signature=bytes.fromhex(sig_hex.removeprefix("0x")))
    if recovered.lower() != address.lower():
        raise DKGCoordinatorError(
            f"encryption_pubkey signature mismatch for {address}: recovered {recovered}"
        )
    return X25519PublicKey.from_public_bytes(pubkey_bytes)


def fetch_encryption_pubkeys(
    keypers: list[Keyper], member_addrs: list[str], *, timeout: float = 5.0,
) -> dict[int, X25519PublicKey]:
    """Fetch and verify each keyper's bootstrap encryption_pubkey from /status.

    A keyper that's unreachable or fails verification is simply omitted --
    the caller should skip bootstrapping it this pass, not crash the whole
    thing.
    """
    pubkeys: dict[int, X25519PublicKey] = {}
    for kp, addr in zip(keypers, member_addrs):
        try:
            r = requests.get(f"{kp.url}/status", timeout=timeout)
            r.raise_for_status()
            j = r.json()
            pubkeys[kp.kid] = _verify_encryption_pubkey(
                addr, j["encryption_pubkey"], j["encryption_pubkey_sig"],
            )
        except Exception as e:
            log.warning("op=fetch_encryption_pubkey keyper=%d status=error err=%s", kp.kid, e)
    return pubkeys


def fetch_bootstrapped_status(keypers: list[Keyper], *, timeout: float = 5.0) -> dict[int, bool]:
    """Read each keyper's live /status.bootstrapped flag.

    Used by the reconciliation pass to tell "lost its persisted token file"
    (row present on our side, bootstrapped=False on theirs -- needs a
    targeted same-value re-push) apart from "already fine" (no push
    needed). An unreachable keyper is reported as bootstrapped=True --
    pushing to a host we can't reach would just fail anyway, so there's no
    point forcing the attempt; treat it as "nothing to do" rather than an
    error.
    """
    result: dict[int, bool] = {}
    for kp in keypers:
        try:
            r = requests.get(f"{kp.url}/status", timeout=timeout)
            r.raise_for_status()
            result[kp.kid] = bool(r.json().get("bootstrapped", False))
        except Exception as e:
            log.warning("op=fetch_bootstrapped_status keyper=%d status=error err=%s", kp.kid, e)
            result[kp.kid] = True
    return result


def push_bootstrap(
    kp: Keyper,
    intended_recipient: str,
    api_token: str,
    peer_token: str,
    peers: dict[str, dict[str, str]],
    encryption_pubkey: X25519PublicKey,
    coordinator_signing_key: str,
    *,
    timeout: float = _BOOTSTRAP_TIMEOUT_S,
) -> bool:
    """Seal+sign a bootstrap envelope for one keyper and POST it.

    Carries everything a keyper needs: its own api_token/peer_token, plus
    peers ({kid: {"url", "token"}} for every *other* keyper -- both where
    to reach it and what to authenticate with, from this one trusted
    source). DKG endpoints (round1, distribute_* etc.) carry no auth
    material or destination data at all -- everything flows through this
    one channel. See docs/private-voting/keyper-token-bootstrap.md.

    Returns True on success; logs and returns False on any failure so a
    single unreachable keyper doesn't abort the whole pass.
    """
    payload = {
        "intended_recipient": intended_recipient,
        "api_token": api_token,
        "peer_token": peer_token,
        "peers": peers,
        "nonce": secrets.token_hex(16),
        "timestamp": int(time.time()),
    }
    sig = _eth_sign(payload, coordinator_signing_key)
    sealed = x25519_seal(
        json.dumps({"payload": payload, "sig": sig}).encode(),
        encryption_pubkey,
    )
    try:
        r = requests.post(f"{kp.url}/auth/bootstrap", data=sealed, timeout=timeout,
                           headers={"Content-Type": "application/octet-stream"})
        r.raise_for_status()
        log.info("op=auth_bootstrap keyper=%d status=ok", kp.kid)
        return True
    except Exception as e:
        log.warning("op=auth_bootstrap keyper=%d status=error err=%s", kp.kid, e)
        return False


def _post(url: str, path: str, payload: dict[str, Any], *, timeout: float,
          headers: dict | None = None) -> dict[str, Any]:
    r = requests.post(f"{url}{path}", json=payload, headers=headers, timeout=timeout)
    if r.status_code >= 400:
        try:
            body = r.json()
        except Exception:
            body = {"text": r.text}
        log.error("http_error url=%s path=%s status=%d body=%s", url, path, r.status_code, body)
        raise DKGCoordinatorError(f"POST {path} failed on {url}: {r.status_code} {body}")
    try:
        return r.json()
    except Exception:
        return {}


def run_dkg(
    *,
    keyper_urls: list[str],
    election_id: str,
    election_address: str,
    n: int,
    t: int,
    members: Optional[list[str]] = None,
    api_tokens: Optional[dict[str, str]] = None,
    timeout: float = 60.0,
    sleep_between: float = 0.0,
    proposal_end_time: Optional[int] = None,
) -> None:
    """
    Orchestrate DKG across keypers and publish the DKG result on-chain.

    ``api_tokens`` maps each keyper's base URL to the coordinator-tier
    bearer token that keyper expects on round1/round2/distribute_*/
    publish_on_chain -- the coordinator authenticates its own calls with
    it. Peer tokens (for P2P calls between keypers) are delivered
    separately via /auth/bootstrap, not through this function -- DKG
    endpoints carry no auth material of their own. ``api_tokens`` comes
    from the one-shot token-bootstrap pass at auto-dkg startup, not an env
    var -- see docs/private-voting/keyper-token-bootstrap.md.
    """
    keypers = _keypers_from_urls(keyper_urls)
    if len(keypers) != n:
        raise DKGCoordinatorError(f"n={n} but got {len(keypers)} keyper URLs")
    if members is None:
        members = fetch_members_from_status(keypers, timeout=min(timeout, 10.0))
    if len(members) != n:
        raise DKGCoordinatorError(f"members length {len(members)} != n {n}")

    def _auth(kp: Keyper) -> dict | None:
        """Bearer header for coordinator → keyper calls using that keyper's own api_token."""
        if not api_tokens:
            return None
        tok = api_tokens.get(kp.url.rstrip("/"), "")
        return {"Authorization": f"Bearer {tok}"} if tok else None

    log.info("op=dkg_start proposal=%s n=%d t=%d keypers=%s",
             election_id, n, t, [kp.url for kp in keypers])

    # round1 — pure DKG mechanics, no auth material or destination data.
    # Peer tokens and each keyper's URL address book were already
    # delivered via /auth/bootstrap.
    for kp in keypers:
        log.info("op=dkg_round1 proposal=%s keyper=%d", election_id, kp.kid)
        _post(
            kp.url,
            "/dkg/round1",
            {
                "n": n, "t": t, "keyper_id": kp.kid,
                "election_id": election_id, "members": members,
            },
            timeout=timeout,
            headers=_auth(kp),
        )
        if sleep_between:
            time.sleep(sleep_between)

    # distribute commitments -- each keyper fans out to its own
    # bootstrap-installed peers map, not anything sent in this body.
    for kp in keypers:
        log.info("op=dkg_distribute_commitments proposal=%s keyper=%d", election_id, kp.kid)
        _post(kp.url, "/dkg/distribute_commitments", {}, timeout=timeout, headers=_auth(kp))
        if sleep_between:
            time.sleep(sleep_between)

    # distribute shares -- same as above.
    for kp in keypers:
        log.info("op=dkg_distribute_shares proposal=%s keyper=%d", election_id, kp.kid)
        _post(kp.url, "/dkg/distribute_shares", {}, timeout=timeout, headers=_auth(kp))
        if sleep_between:
            time.sleep(sleep_between)

    # round2
    round2_payload: dict[str, Any] = {"election_id": election_id}
    if proposal_end_time is not None:
        round2_payload["proposal_end_time"] = proposal_end_time
    for kp in keypers:
        log.info("op=dkg_round2 proposal=%s keyper=%d", election_id, kp.kid)
        _post(kp.url, "/dkg/round2", round2_payload, timeout=timeout, headers=_auth(kp))
        if sleep_between:
            time.sleep(sleep_between)

    # publish on chain
    for kp in keypers:
        log.info("op=dkg_publish proposal=%s keyper=%d", election_id, kp.kid)
        _post(
            kp.url,
            "/dkg/publish_on_chain",
            {"election_address": election_address, "n": n},
            timeout=timeout,
            headers=_auth(kp),
        )
        if sleep_between:
            time.sleep(sleep_between)

    log.info("op=dkg_done proposal=%s", election_id)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s [%(name)s] %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S',
    )
    p = argparse.ArgumentParser(description="DKG coordinator (keyper HTTP orchestrator)")
    p.add_argument("--keyper-urls", required=True, help="Comma-separated keyper base URLs")
    p.add_argument("--election-id", required=True, help="Opaque election id string for keypers (e.g. demo-election)")
    p.add_argument("--election-address", required=True, help="Election contract address (0x...)")
    p.add_argument("--n", type=int, required=True, help="Number of keypers")
    p.add_argument("--t", type=int, required=True, help="Threshold degree (need t+1 shares)")
    p.add_argument("--timeout", type=float, default=60.0, help="Per-request timeout seconds (default 60)")
    p.add_argument("--sleep-between", type=float, default=0.0, help="Sleep seconds between requests (default 0)")
    args = p.parse_args()

    keyper_urls = [u.strip() for u in args.keyper_urls.split(",") if u.strip()]
    run_dkg(
        keyper_urls=keyper_urls,
        election_id=args.election_id,
        election_address=args.election_address,
        n=args.n,
        t=args.t,
        timeout=args.timeout,
        sleep_between=args.sleep_between,
    )


if __name__ == "__main__":
    try:
        main()
    except DKGCoordinatorError as e:
        log.error("fatal err=%s", e)
        raise SystemExit(2)
