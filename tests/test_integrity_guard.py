"""M5: local manifest is advisory; no untrusted code/vault auto-restores."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qpgen.guard import IntegrityGuard


class IntegrityGuardM5Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "code"
        self.root.mkdir()
        self.target = self.root / "sample.py"
        self.target.write_text("print('baseline')\n")
        self.backup = Path(self.tmp.name) / "backups"
        self.guard = IntegrityGuard(
            root_dir=self.root,
            manifest_path=self.root / "manifest.json",
            backup_dir=self.backup,
        )
        self.original = IntegrityGuard._critical_files
        self.guard._critical_files = lambda: ["sample.py"]

    def test_first_run_is_untrusted_baseline_not_attestation(self):
        ok, message = self.guard.verify({"version": 2})
        self.assertTrue(ok)
        self.assertIn("not trusted attestation", message)
        self.assertTrue(self.guard.manifest_path.exists())

    def test_matching_local_baseline_is_not_attestation(self):
        self.guard.verify({"version": 2})
        ok, message = self.guard.verify({"version": 2})
        self.assertTrue(ok)
        self.assertIn("not trusted attestation", message)

    def test_code_change_detected_without_restoration(self):
        self.guard.verify({"version": 2})
        self.target.write_text("print('modified')\n")
        ok, msg = self.guard.verify({"version": 2})
        self.assertFalse(ok)
        self.assertIn("sample.py", msg)
        self.assertEqual(self.target.read_text(), "print('modified')\n")

    def test_vault_header_change_detected_non_destructively(self):
        self.guard.verify({"version": 2})
        ok, msg = self.guard.verify({"version": 1})
        self.assertFalse(ok)
        self.assertIn("vault_header changed", msg)

    def test_no_automatic_code_backups_created(self):
        with patch.object(self.guard, "create_code_backups", side_effect=AssertionError("unexpected code snapshot")):
            self.guard.verify({"version": 2})
        self.assertFalse(self.backup.exists())

    def test_restore_code_backups_fails_closed_without_touching_code(self):
        self.guard.verify({"version": 2})
        self.target.write_text("print('modified')\n")
        with patch.object(self.guard, "_ensure_backup_dir", side_effect=AssertionError("unexpected backup access")):
            ok, msg = self.guard.restore_code_backups()
        self.assertFalse(ok)
        self.assertIn("disabled", msg)
        self.assertEqual(self.target.read_text(), "print('modified')\n")

    def test_gui_has_no_automatic_repair_call_sites(self):
        gui = (Path(__file__).parents[1] / "qpgen" / "gui_qt.py").read_text()
        self.assertNotIn('self._restore_from_backups(', gui)
        self.assertNotIn('guard.restore_code_backups(', gui)
        self.assertNotIn('self.vault.restore_from_backup(', gui)
        self.assertIn('integrity_local_warning_accepted', gui)
        self.assertIn('self._integrity_live_alerted = True', gui)
        self.assertIn('self._integrity_live_alerted = False', gui)
        self.assertIn('QMessageBox.Ok', gui)


if __name__ == "__main__":
    unittest.main()
