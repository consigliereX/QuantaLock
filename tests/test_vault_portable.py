"""M3 compatibility tests: temporary synthetic v1/v2 vaults only."""
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet
from qpgen.vault import QuantumVault, QuantumVaultError, VaultEntry


class PortableVaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "synthetic-vault.json"

    def _version(self):
        return json.loads(self.path.read_text())["version"]

    def _legacy_key(self, password, salt):
        # Deterministic stand-in for the old hardware binding, never touching HOME.
        return base64.urlsafe_b64encode(hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt + b"synthetic-v1-binding", 2000, 32
        ))

    def _legacy_file(self, password="old-master", entries=None):
        entries = entries if entries is not None else [
            {"label":"legacy", "username":"test", "password":"before",
             "created_at":"", "last_rotated_at":""}
        ]
        salt = os.urandom(32)
        encrypted = Fernet(self._legacy_key(password, salt)).encrypt(
            json.dumps(entries).encode("utf-8")
        )
        self.path.write_text(json.dumps({
            "version":1,
            "q_salt":base64.b64encode(salt).decode("ascii"),
            "data":base64.b64encode(encrypted).decode("ascii"),
        }), encoding="utf-8")

    def test_new_vault_defaults_to_portable_v2(self):
        q = QuantumVault(self.path)
        with patch.object(q, "_derive_key", side_effect=AssertionError("v1 called")):
            q.initialize("new-master")
        self.assertEqual(self._version(), 2)
        self.assertEqual(len(q._q_salt), 32)

    def test_v2_round_trip_without_legacy_binding(self):
        q = QuantumVault(self.path)
        q.initialize("new-master")
        q.add_or_update(VaultEntry("entry", "alice", "secret"))
        q.save()
        opened = QuantumVault(self.path)
        with patch.object(opened, "_derive_key", side_effect=AssertionError("v1 called")):
            opened.unlock("new-master")
        self.assertEqual(opened.entries[0].password, "secret")
        self.assertEqual(opened._vault_version, 2)

    def test_v2_bad_password_leaves_file_unchanged(self):
        QuantumVault(self.path).initialize("new-master")
        before = self.path.read_bytes()
        with self.assertRaises(QuantumVaultError):
            QuantumVault(self.path).unlock("wrong")
        self.assertEqual(self.path.read_bytes(), before)

    def test_v1_unlock_and_save_stay_v1(self):
        self._legacy_file()
        q = QuantumVault(self.path)
        q._derive_key = self._legacy_key
        q.unlock("old-master")
        self.assertEqual(q.entries[0].password, "before")
        q.add_or_update(VaultEntry("legacy", "test", "after"))
        q.save()
        self.assertEqual(self._version(), 1)
        r = QuantumVault(self.path)
        r._derive_key = self._legacy_key
        r.unlock("old-master")
        self.assertEqual(r.entries[0].password, "after")

    def test_v1_master_rotation_retains_v1(self):
        self._legacy_file()
        q = QuantumVault(self.path)
        q._derive_key = self._legacy_key
        q.change_master_password("old-master", "next-master")
        self.assertEqual(self._version(), 1)
        r = QuantumVault(self.path)
        r._derive_key = self._legacy_key
        r.unlock("next-master")
        self.assertEqual(r.entries[0].password, "before")

    def test_v2_rotation_and_previous_generation_restore(self):
        q = QuantumVault(self.path)
        q.initialize("first-master")
        q.add_or_update(VaultEntry("entry", "alice", "secret"))
        q.save()
        q.change_master_password("first-master", "second-master")
        self.assertEqual(self._version(), 2)
        after = QuantumVault(self.path)
        after.unlock("second-master")
        self.assertEqual(after.entries[0].password, "secret")
        self.assertTrue(after.restore_from_backup())
        restored = QuantumVault(self.path)
        restored.unlock("first-master")
        self.assertEqual(restored.entries[0].password, "secret")

    def test_reject_unknown_vault_version(self):
        self._legacy_file()
        data = json.loads(self.path.read_text())
        data["version"] = 3
        self.path.write_text(json.dumps(data))
        with self.assertRaises(QuantumVaultError):
            QuantumVault(self.path).unlock("old-master")


if __name__ == "__main__":
    unittest.main()
