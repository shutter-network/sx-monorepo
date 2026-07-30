"""Regression tests for dynamic (non-static) keyper DKG-index assignment.

See docs/private-voting/keyper-id-removal-plan.md. A keyper no longer
configures its own index (`--id`/`KEYPER_ID`) -- it adopts whatever
`keyper_id` auto-dkg sends at `/dkg/round1` time, fresh for every
proposal. These tests lock in the two properties that matter:

  1. A keyper with no id pinned at construction accepts *any* kid at
     round1, including a *different* kid for a later proposal than an
     earlier one already set -- this is the exact case a naive
     "keyper_meta['id'] is not None" mismatch check would wrongly reject.
  2. Each proposal's resolved kid is persisted *per proposal*
     (`DkgEntry.keyper_id`), not as a single global that a later
     proposal's DKG could clobber.
"""

from __future__ import annotations

import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from eth_account import Account

import keyper
import keyper_persistence


class DynamicKeyperIdTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "KEYPER_STATE_DIR": self._tmpdir.name,
                "KEYPER_DKG_RETENTION_TIME": "0",
                "KEYPER_DKG_PRUNE_INTERVAL_S": "0",
            },
            clear=False,
        )
        self._env_patch.start()
        self.private_key = "0x" + ("33" * 32)
        self.address = Account.from_key(self.private_key).address
        # Real deployment path: no keyper_id pinned at construction.
        self.app = keyper.create_keyper_app(signing_key=self.private_key)
        self.client = self.app.test_client()

    def tearDown(self):
        self._env_patch.stop()
        self._tmpdir.cleanup()

    def _run_dkg(self, kid: int, n: int, election_id: str) -> dict:
        r = self.client.post("/dkg/round1", json={
            "n": n, "t": 0, "keyper_id": kid,
            "election_id": election_id, "members": [self.address] * n,
        })
        self.assertEqual(r.status_code, 200, r.get_json())
        self.client.post("/dkg/distribute_commitments", json={})
        self.client.post("/dkg/distribute_shares", json={})
        r = self.client.post("/dkg/round2", json={"election_id": election_id})
        self.assertEqual(r.status_code, 200, r.get_json())
        body = r.get_json()
        self.assertTrue(body["verified"], body)
        return body

    def test_no_pinned_id_accepts_any_kid(self):
        status = self.client.get("/status").get_json()
        self.assertIsNone(status["keyper_id"])

        self._run_dkg(kid=1, n=2, election_id="propA")
        self.assertEqual(self.client.get("/status").get_json()["keyper_id"], 1)

    def test_later_proposal_may_assign_a_different_kid(self):
        # This is exactly the case a static/pinned mismatch check would
        # reject: keyper_meta["id"] is already 1 from propA when propB's
        # round1 arrives with kid=2.
        self._run_dkg(kid=1, n=2, election_id="propA")
        body = self._run_dkg(kid=2, n=2, election_id="propB")
        self.assertEqual(body["keyper_id"], 2)
        self.assertEqual(self.client.get("/status").get_json()["keyper_id"], 2)

    def test_pinned_id_still_rejects_a_real_mismatch(self):
        # Tests/dev callers that already know their index a priori keep a
        # real mismatch check -- a genuine misconfiguration still fails
        # loud, same as before this change.
        app = keyper.create_keyper_app(keyper_id=1, signing_key=self.private_key)
        client = app.test_client()
        r = client.post("/dkg/round1", json={
            "n": 2, "t": 0, "keyper_id": 2,
            "election_id": "propA", "members": [self.address] * 2,
        })
        self.assertEqual(r.status_code, 400)
        self.assertIn("mismatch", r.get_json()["error"].lower())

    def test_each_proposal_persists_its_own_kid_independently(self):
        self._run_dkg(kid=1, n=2, election_id="propA")
        self._run_dkg(kid=2, n=2, election_id="propB")

        # Simulate a restart: fresh load from the same on-disk state,
        # independent of the live (mutated) keyper_meta["id"] in-process.
        fernet = keyper._derive_fernet(self.private_key)
        completed: dict = {}
        keyper_persistence.load_dkg_secrets(fernet, completed, logging.getLogger("test"))

        self.assertEqual(completed["propA"].keyper_id, 1)
        self.assertEqual(completed["propB"].keyper_id, 2)


if __name__ == "__main__":
    unittest.main()
