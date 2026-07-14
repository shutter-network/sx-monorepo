"""Unit tests for keyper on-disk persistence: DKG secrets, the bootstrap
encryption keypair, and installed bearer tokens -- see keyper_persistence.py."""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

# Allow: python tests/test_keyper_persistence.py (from services/keypers/)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from crypto.primitives import G2, point_eq, point_multiply
from keyper_persistence import (
    DkgEntry,
    load_bootstrap_tokens,
    load_dkg_secrets,
    load_or_create_encryption_key,
    prune_expired_dkg_secrets,
    save_bootstrap_tokens,
    save_dkg_secrets,
)


class DkgPersistenceTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._env_patch = mock.patch.dict(
            os.environ,
            {"KEYPER_STATE_DIR": self._tmpdir.name},
            clear=False,
        )
        self._env_patch.start()
        self.fernet = Fernet(Fernet.generate_key())
        self.logger = mock.Mock()

    def tearDown(self):
        self._env_patch.stop()
        self._tmpdir.cleanup()

    def test_save_load_round_trip(self):
        completed = {}
        completed["0xabc"] = DkgEntry(42)
        save_dkg_secrets(self.fernet, completed)

        loaded = {}
        load_dkg_secrets(self.fernet, loaded, self.logger)
        self.assertEqual(loaded["0xabc"].combined_share, 42)
        self.assertIsNone(loaded["0xabc"].expires_at)
        self.assertTrue(point_eq(loaded["0xabc"].public_key_share, point_multiply(G2, 42)))

    def test_expires_at_round_trip(self):
        expires_at = int(time.time()) + 3600
        completed = {
            "0xabc": DkgEntry(7, expires_at=expires_at),
        }
        save_dkg_secrets(self.fernet, completed)

        loaded = {}
        load_dkg_secrets(self.fernet, loaded, self.logger)
        self.assertEqual(loaded["0xabc"].expires_at, expires_at)

    def test_prune_removes_only_expired(self):
        past = int(time.time()) - 10
        future = int(time.time()) + 3600
        completed = {
            "0xold": DkgEntry(1, expires_at=past),
            "0xnew": DkgEntry(2, expires_at=future),
            "0xopen": DkgEntry(3),
        }
        removed = prune_expired_dkg_secrets(self.fernet, completed, self.logger)
        self.assertEqual(removed, ["0xold"])
        self.assertNotIn("0xold", completed)
        self.assertIn("0xnew", completed)
        self.assertIn("0xopen", completed)

        loaded = {}
        load_dkg_secrets(self.fernet, loaded, self.logger)
        self.assertNotIn("0xold", loaded)

    def test_expires_at_is_integer(self):
        expires_at = int(time.time()) + 172800
        completed = {"0xabc": DkgEntry(9, expires_at=expires_at)}
        save_dkg_secrets(self.fernet, completed)

        loaded = {}
        load_dkg_secrets(self.fernet, loaded, self.logger)
        self.assertIsInstance(loaded["0xabc"].expires_at, int)
        self.assertEqual(loaded["0xabc"].expires_at, expires_at)


class BootstrapTokenPersistenceTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._env_patch = mock.patch.dict(
            os.environ,
            {"KEYPER_STATE_DIR": self._tmpdir.name},
            clear=False,
        )
        self._env_patch.start()
        self.fernet = Fernet(Fernet.generate_key())
        self.logger = mock.Mock()

    def tearDown(self):
        self._env_patch.stop()
        self._tmpdir.cleanup()

    def test_returns_none_when_never_bootstrapped(self):
        # A fresh keyper has no bootstrap_tokens.enc yet -- must return None,
        # not raise, so the caller stays in the fail-closed pre-bootstrap
        # state rather than crashing at startup.
        self.assertIsNone(load_bootstrap_tokens(self.fernet, self.logger))

    def test_save_load_round_trip(self):
        peers = {
            "2": {"url": "http://keyper2:5002", "token": "peer-tok-2"},
            "3": {"url": "http://keyper3:5003", "token": "peer-tok-3"},
        }
        save_bootstrap_tokens(self.fernet, "api-tok-1", "peer-tok-1", peers)
        loaded = load_bootstrap_tokens(self.fernet, self.logger)
        self.assertEqual(loaded["api_token"], "api-tok-1")
        self.assertEqual(loaded["peer_token"], "peer-tok-1")
        self.assertEqual(loaded["peers"], peers)

    def test_overwrite_replaces_previous_values(self):
        # A forced rotation (or any later /auth/bootstrap call) must replace
        # the file wholesale, not merge with what was there before.
        old_peers = {"2": {"url": "http://keyper2:5002", "token": "old-2"}}
        new_peers = {
            "2": {"url": "http://keyper2:5002", "token": "new-2"},
            "3": {"url": "http://keyper3:5003", "token": "new-3"},
        }
        save_bootstrap_tokens(self.fernet, "old-api", "old-peer", old_peers)
        save_bootstrap_tokens(self.fernet, "new-api", "new-peer", new_peers)

        loaded = load_bootstrap_tokens(self.fernet, self.logger)
        self.assertEqual(loaded["api_token"], "new-api")
        self.assertEqual(loaded["peer_token"], "new-peer")
        self.assertEqual(loaded["peers"], new_peers)

    def test_wrong_key_returns_none_not_raise(self):
        save_bootstrap_tokens(self.fernet, "api-tok", "peer-tok", {})
        wrong_fernet = Fernet(Fernet.generate_key())
        self.assertIsNone(load_bootstrap_tokens(wrong_fernet, self.logger))


class EncryptionKeyPersistenceTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._env_patch = mock.patch.dict(
            os.environ,
            {"KEYPER_STATE_DIR": self._tmpdir.name},
            clear=False,
        )
        self._env_patch.start()
        self.fernet = Fernet(Fernet.generate_key())
        self.logger = mock.Mock()

    def tearDown(self):
        self._env_patch.stop()
        self._tmpdir.cleanup()

    def test_first_call_creates_a_key(self):
        key = load_or_create_encryption_key(self.fernet, self.logger)
        self.assertIsInstance(key, X25519PrivateKey)

    def test_second_call_loads_the_same_key(self):
        # The coordinator caches this keyper's encryption_pubkey across
        # restarts -- if this regenerated a new key every call, that cache
        # would go stale and every bootstrap push would fail to decrypt.
        first = load_or_create_encryption_key(self.fernet, self.logger)
        second = load_or_create_encryption_key(self.fernet, self.logger)
        self.assertEqual(
            first.public_key().public_bytes_raw(),
            second.public_key().public_bytes_raw(),
        )

    def test_wrong_key_regenerates_rather_than_raising(self):
        first = load_or_create_encryption_key(self.fernet, self.logger)
        wrong_fernet = Fernet(Fernet.generate_key())
        regenerated = load_or_create_encryption_key(wrong_fernet, self.logger)
        self.assertIsInstance(regenerated, X25519PrivateKey)
        self.assertNotEqual(
            first.public_key().public_bytes_raw(),
            regenerated.public_key().public_bytes_raw(),
        )


if __name__ == "__main__":
    unittest.main()
