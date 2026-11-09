"""M2 vault file durability/recovery tests (synthetic temporary vaults only)."""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from qpgen.vault import QuantumVault, QuantumVaultError, VaultEntry


class VaultIOTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "vault.json"
        self.vault = QuantumVault(self.path)
        # Avoid local hardware binding, persistent secrets, and full PBKDF cost.
        # The real Fernet encryption and vault serialization remain in use.
        self.vault._derive_key = lambda password, salt: base64.urlsafe_b64encode(
            hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 1000, 32)
        )
        self.vault.initialize("test-master")

    def _open(self):
        other = QuantumVault(self.path)
        other._derive_key = self.vault._derive_key
        other.unlock("test-master")
        return other

    def _write_version(self, password):
        self.vault.add_or_update(VaultEntry("label", "name", password))
        self.vault.save()

    def test_csprng_salt_and_private_file(self):
        self.assertEqual(len(self.vault._q_salt), 32)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(self._open().entries, [])

    def test_backup_contains_previous_generation(self):
        initial = self.path.read_bytes()
        self._write_version("one")
        self.assertEqual(self.vault._backup_path().read_bytes(), initial)
        first = self.path.read_bytes()
        self._write_version("two")
        self.assertEqual(self.vault._backup_path().read_bytes(), first)
        self.assertEqual(self._open().entries[0].password, "two")

    def test_interrupted_publish_preserves_existing_file(self):
        self._write_version("one")
        before = self.path.read_bytes()
        self.vault.add_or_update(VaultEntry("label", "name", "two"))
        original_replace = os.replace

        def fail_main_replace(src, dst):
            if Path(dst) == self.path:
                raise OSError("injected power-loss-before-rename")
            return original_replace(src, dst)

        with patch("qpgen.vault.os.replace", side_effect=fail_main_replace):
            with self.assertRaises(QuantumVaultError):
                self.vault.save()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self._open().entries[0].password, "one")
        self.assertEqual(list(self.path.parent.glob("*.tmp")), [])

    def test_backup_failure_aborts_overwrite(self):
        self._write_version("one")
        before = self.path.read_bytes()
        self.vault.add_or_update(VaultEntry("label", "name", "two"))
        with patch.object(self.vault, "backup_to_disk", side_effect=OSError("disk full")):
            with self.assertRaises(QuantumVaultError):
                self.vault.save()
        self.assertEqual(self.path.read_bytes(), before)

    def test_restore_preserves_corrupt_current_and_restores_previous(self):
        self._write_version("one")
        self._write_version("two")
        current = self.path.read_bytes()
        self.assertTrue(self.vault.restore_from_backup())
        self.assertEqual(self._open().entries[0].password, "one")
        copies = list(self.path.parent.glob("vault.json.corrupt.*"))
        self.assertEqual(len(copies), 1)
        self.assertEqual(copies[0].read_bytes(), current)
        self.assertIsNone(self.vault._fernet)

    def test_invalid_backup_does_not_destroy_current(self):
        self._write_version("one")
        current = self.path.read_bytes()
        self.vault._backup_path().write_text('{"version":1,"q_salt":"bad","data":"bad"}')
        self.assertFalse(self.vault.restore_from_backup())
        self.assertEqual(self.path.read_bytes(), current)
        self.assertEqual(self._open().entries[0].password, "one")


if __name__ == "__main__":
    unittest.main()
