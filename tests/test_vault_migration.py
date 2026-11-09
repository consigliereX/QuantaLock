"""M4 migration tests; all vaults/salts/entries are synthetic and temporary."""
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


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "testvault.json"
        self._create_legacy()

    @staticmethod
    def _old_key(password, salt):
        return base64.urlsafe_b64encode(hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt + b"synthetic-hardware", 1000, 32
        ))

    def _create_legacy(self):
        salt = os.urandom(32)
        self.entries = [dict(label="test", username="user", password="testsecret",
                             created_at="2025-01-01T00:00:00+00:00", last_rotated_at="")]
        c = Fernet(self._old_key("old-master", salt)).encrypt(json.dumps(self.entries).encode())
        self.path.write_text(json.dumps(dict(version=1,
            q_salt=base64.b64encode(salt).decode(),
            data=base64.b64encode(c).decode())))
        self.vault = QuantumVault(self.path)
        self.vault._derive_key = self._old_key  # Never access HOME/device secret.

    def _version(self):
        return json.loads(self.path.read_text())["version"]

    def _migrate(self):
        return self.vault.migrate_v1_to_v2("old-master")

    def test_migration_round_trip_and_immutable_v1_archive(self):
        original = self.path.read_bytes()
        archive = self._migrate()
        self.assertEqual(self._version(), 2)
        self.assertEqual(archive.read_bytes(), original)
        opened = QuantumVault(self.path)
        opened.unlock("old-master")
        self.assertEqual([e.__dict__ for e in opened.entries], self.entries)
        self.assertEqual(self.vault._vault_version, 2)

    def test_wrong_master_cannot_modify_v1(self):
        before = self.path.read_bytes()
        with self.assertRaises(QuantumVaultError):
            self.vault.migrate_v1_to_v2("not-the-password")
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(list(self.path.parent.glob("*.pre-v2-*.bak")))

    def test_v2_refuses_second_migration(self):
        self._migrate()
        before = self.path.read_bytes()
        with self.assertRaises(QuantumVaultError):
            self._migrate()
        self.assertEqual(self.path.read_bytes(), before)

    def test_archive_failure_leaves_v1_unchanged(self):
        before = self.path.read_bytes()
        with patch("qpgen.vault._atomic_write_bytes", side_effect=OSError("disk full")):
            with self.assertRaises(QuantumVaultError):
                self._migrate()
        self.assertEqual(self.path.read_bytes(), before)

    def test_interrupted_publish_leaves_v1_unchanged(self):
        before = self.path.read_bytes()
        import qpgen.vault as module
        original_write = module._atomic_write_bytes
        def fails_main(target, data):
            if Path(target) == self.path:
                raise OSError("simulated interrupted publish")
            return original_write(target, data)
        with patch("qpgen.vault._atomic_write_bytes", side_effect=fails_main):
            with self.assertRaises(QuantumVaultError):
                self._migrate()
        self.assertEqual(self.path.read_bytes(), before)

    def test_failed_v2_authentication_restores_v1(self):
        before = self.path.read_bytes()
        # Instance-only mismatch: candidate works locally, fresh verifier fails.
        with patch.object(self.vault, "_derive_portable_key", return_value=Fernet.generate_key()):
            with self.assertRaises(QuantumVaultError):
                self._migrate()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self._version(), 1)
        self.assertEqual(len(list(self.path.parent.glob("*.pre-v2-*.bak"))), 1)

    def test_explicit_rollback_restores_old_data(self):
        archive = self._migrate()
        v2bytes = self.path.read_bytes()
        snapshot = self.vault.restore_v1_migration_backup(archive, "old-master")
        self.assertEqual(self._version(), 1)
        self.assertEqual(snapshot.read_bytes(), v2bytes)
        self.assertEqual([e.__dict__ for e in self.vault.entries], self.entries)

    def test_wrong_rollback_password_preserves_v2(self):
        archive = self._migrate()
        current = self.path.read_bytes()
        with self.assertRaises(QuantumVaultError):
            self.vault.restore_v1_migration_backup(archive, "wrong")
        self.assertEqual(self.path.read_bytes(), current)

    def test_rollback_rejects_outside_archive(self):
        self._migrate()
        current = self.path.read_bytes()
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td) / (self.path.name + ".pre-v2-bad.bak")
            fake.write_bytes(self.path.read_bytes())
            with self.assertRaises(QuantumVaultError):
                self.vault.restore_v1_migration_backup(fake, "old-master")
        self.assertEqual(self.path.read_bytes(), current)


if __name__ == "__main__":
    unittest.main()
