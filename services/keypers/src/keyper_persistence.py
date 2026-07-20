"""Encrypted on-disk persistence for a keyper's durable state.

Three separate files under KEYPER_STATE_DIR, all Fernet-encrypted with a key
derived from the keyper's own signing key, none sharing a file with another:
  - dkg_secrets.enc        per-proposal DKG combined shares (+ retention/pruning)
  - encryption_key.enc     the X25519 keypair used to decrypt /auth/bootstrap
                           payloads -- persisted so the coordinator's cached
                           encryption_pubkey for this keyper never goes stale
  - bootstrap_tokens.enc   the installed api_token/peer_token/peers map
                           ({kid: {url, token}} for every other keyper),
                           so a restart needs no re-bootstrap at all
"""

from __future__ import annotations

import json
import logging
import os
import pathlib
import threading
import time
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from crypto.primitives import G2, point_multiply


@dataclass
class DkgEntry:
    """Per-proposal DKG secret — mirrors the on-disk JSON row."""

    combined_share: int
    expires_at: int | None = None

    @property
    def public_key_share(self):
        return point_multiply(G2, self.combined_share)


def retention_time() -> float:
    raw = os.environ.get("KEYPER_DKG_RETENTION_TIME")
    if raw is None:
        raise RuntimeError(
            "KEYPER_DKG_RETENTION_TIME is required "
            "(set in docker-compose or .env; 0 disables pruning)"
        )
    return float(raw)


def prune_interval_s() -> float:
    return float(os.environ.get("KEYPER_DKG_PRUNE_INTERVAL_S", "3600"))


def state_file() -> pathlib.Path:
    d = pathlib.Path(os.environ.get("KEYPER_STATE_DIR", "/keyper-state"))
    d.mkdir(parents=True, exist_ok=True)
    return d / "dkg_secrets.enc"


def _entry_from_raw(raw: dict) -> DkgEntry:
    share = int(raw["share"], 16)
    raw_expires = raw.get("expires_at")
    expires_at = int(raw_expires) if raw_expires is not None else None
    return DkgEntry(share, expires_at=expires_at)


def save_dkg_secrets(fernet: Fernet, completed_dkgs: dict[str, DkgEntry]) -> None:
    data = {}
    for pid, entry in completed_dkgs.items():
        row: dict[str, float | str] = {"share": hex(entry.combined_share)}
        if entry.expires_at is not None:
            row["expires_at"] = entry.expires_at
        data[pid] = row
    encrypted = fernet.encrypt(json.dumps(data).encode())
    path = state_file()
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(encrypted)
    os.replace(tmp, path)


def load_dkg_secrets(fernet: Fernet, completed_dkgs: dict[str, DkgEntry], logger: logging.Logger) -> None:
    path = state_file()
    if not path.exists():
        return
    try:
        data = json.loads(fernet.decrypt(path.read_bytes()))
        for pid, raw in data.items():
            completed_dkgs[pid] = _entry_from_raw(raw)
        logger.info("op=load_dkg_secrets status=ok proposals=%d", len(data))
    except InvalidToken:
        logger.error(
            "op=load_dkg_secrets status=error reason=decryption_failed "
            "(wrong KEYPER_PRIVATE_KEY or tampered file — starting with empty state)"
        )
    except Exception as err:
        logger.error("op=load_dkg_secrets status=error err=%s", err)


def prune_expired_dkg_secrets(
    fernet: Fernet,
    completed_dkgs: dict[str, DkgEntry],
    logger: logging.Logger,
) -> list[str]:
    now = time.time()
    expired = [
        pid
        for pid, entry in completed_dkgs.items()
        if entry.expires_at is not None and entry.expires_at <= now
    ]
    if not expired:
        return []
    for pid in expired:
        del completed_dkgs[pid]
    save_dkg_secrets(fernet, completed_dkgs)
    logger.info("op=prune_dkg_secrets status=ok removed=%d proposals=%s", len(expired), expired)
    return expired


def encryption_key_file() -> pathlib.Path:
    d = pathlib.Path(os.environ.get("KEYPER_STATE_DIR", "/keyper-state"))
    d.mkdir(parents=True, exist_ok=True)
    return d / "encryption_key.enc"


def load_or_create_encryption_key(fernet: Fernet, logger: logging.Logger) -> X25519PrivateKey:
    """Load this keyper's X25519 bootstrap-encryption private key, generating
    and persisting one on first run. Persisted (not regenerated per restart)
    so the coordinator's cached ``encryption_pubkey`` for this keyper stays
    valid across restarts -- see keyper-token-bootstrap.md, step 2."""
    path = encryption_key_file()
    if path.exists():
        try:
            raw = fernet.decrypt(path.read_bytes())
            logger.info("op=load_encryption_key status=ok")
            return X25519PrivateKey.from_private_bytes(raw)
        except InvalidToken:
            logger.error(
                "op=load_encryption_key status=error reason=decryption_failed "
                "(wrong KEYPER_PRIVATE_KEY or tampered file -- regenerating)"
            )

    key = X25519PrivateKey.generate()
    encrypted = fernet.encrypt(key.private_bytes_raw())
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(encrypted)
    os.replace(tmp, path)
    logger.info("op=create_encryption_key status=ok")
    return key


def bootstrap_tokens_file() -> pathlib.Path:
    d = pathlib.Path(os.environ.get("KEYPER_STATE_DIR", "/keyper-state"))
    d.mkdir(parents=True, exist_ok=True)
    return d / "bootstrap_tokens.enc"


def save_bootstrap_tokens(
    fernet: Fernet, api_token: str, peer_token: str, peers: dict[str, dict[str, str]],
) -> None:
    """Persist this keyper's own api_token/peer_token and its outbound
    peers map ({kid: {"url", "token"}} -- both what it needs to reach a
    peer and what to authenticate with, from the same trusted source) --
    a separate encrypted file from dkg_secrets.enc, so a keyper restart
    never needs a fresh /auth/bootstrap call to resume being called *or*
    calling others. Overwritten wholesale on every successful bootstrap
    (first-time or a later forced rotation) -- see keyper-token-bootstrap.md."""
    data = {
        "api_token": api_token,
        "peer_token": peer_token,
        "peers": peers,
    }
    encrypted = fernet.encrypt(json.dumps(data).encode())
    path = bootstrap_tokens_file()
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(encrypted)
    os.replace(tmp, path)


def load_bootstrap_tokens(fernet: Fernet, logger: logging.Logger) -> dict | None:
    """Returns {"api_token", "peer_token", "peers"} if a prior bootstrap
    was persisted, else None (never bootstrapped yet -- the keyper stays
    in the fail-closed pre-bootstrap state)."""
    path = bootstrap_tokens_file()
    if not path.exists():
        return None
    try:
        data = json.loads(fernet.decrypt(path.read_bytes()))
        logger.info("op=load_bootstrap_tokens status=ok")
        return data
    except InvalidToken:
        logger.error(
            "op=load_bootstrap_tokens status=error reason=decryption_failed "
            "(wrong KEYPER_PRIVATE_KEY or tampered file -- starting unbootstrapped)"
        )
        return None
    except Exception as err:
        logger.error("op=load_bootstrap_tokens status=error err=%s", err)
        return None


def start_prune_loop(
    completed_dkgs: dict[str, DkgEntry],
    fernet: Fernet,
    logger: logging.Logger,
    lock: threading.Lock,
) -> None:
    retention_s = retention_time()
    interval = prune_interval_s()
    if retention_s <= 0 or interval <= 0:
        logger.info(
            "op=prune_dkg_secrets status=disabled retention_time_s=%.0f interval_s=%.0f",
            retention_s,
            interval,
        )
        return

    def _loop() -> None:
        while True:
            time.sleep(interval)
            try:
                with lock:
                    prune_expired_dkg_secrets(fernet, completed_dkgs, logger)
            except Exception as err:
                logger.error("op=prune_dkg_secrets status=error err=%s", err)

    thread = threading.Thread(target=_loop, name="dkg-prune", daemon=True)
    thread.start()
    logger.info(
        "op=prune_dkg_secrets status=started interval_s=%.0f retention_time_s=%.0f",
        interval,
        retention_s,
    )
