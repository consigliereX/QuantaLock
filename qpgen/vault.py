"""
Encrypted password vault with versioned key derivation.

New vaults use portable v2 keys derived from the master password and an OS
CSPRNG salt. Existing v1 files retain device binding (see guard.py); they
are never silently migrated.

Vault file format (JSON text):
{
  "version": 1 or 2,
  "q_salt": "<base64>",
  "data": "<base64 ciphertext>"
}
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List
from datetime import datetime, timezone
import json
import base64
import hashlib
import os
import shutil
import tempfile

from cryptography.fernet import Fernet, InvalidToken  # pip install cryptography


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Replace one file atomically using a same-directory, private temp file.

    A crash during the write leaves the existing destination intact. File data
    is synced before replace; directory syncing is attempted where supported.
    """
    path = Path(path)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.chmod(tmp, 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        if os.name == "posix":
            try:
                dirfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            except OSError:
                pass
            else:
                try:
                    os.fsync(dirfd)
                except OSError:
                    pass
                finally:
                    os.close(dirfd)
    finally:
        tmp.unlink(missing_ok=True)


def _default_vault_path() -> Path:
    """
    Choose an OS-specific, user-local path for the vault file instead of
    the current working directory, so the location is less obvious and
    not tied to where the EXE/script is run from.
    """
    if os.name == "nt":
        base = os.getenv("APPDATA")
        base_path = Path(base) if base else Path.home() / "AppData" / "Roaming"
    else:
        base = os.getenv("XDG_DATA_HOME")
        base_path = Path(base) if base else Path.home() / ".local" / "share"

    vault_dir = base_path / "qpgen_vault"
    try:
        vault_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        # Fallback: hidden vault directory in the home folder
        vault_dir = Path.home() / ".qpgen_vault"
        vault_dir.mkdir(parents=True, exist_ok=True)

    return vault_dir / "quantum_vault.bin"


VAULT_FILE = _default_vault_path()
LEGACY_VAULT_VERSION = 1
VAULT_VERSION = 2
KDF_ITERATIONS = 300_000  # Legacy v1; never change for old vaults.
PORTABLE_KDF_ITERATIONS = 600_000  # v2, master-password-only portability.
SUPPORTED_VAULT_VERSIONS = (LEGACY_VAULT_VERSION, VAULT_VERSION)

@dataclass
class VaultEntry:
    label: str
    username: str
    password: str
    # When this entry was first created (UTC ISO string).
    created_at: str = ""
    # When the password was last rotated / changed (UTC ISO string).
    last_rotated_at: str = ""

class QuantumVaultError(Exception):
    """Generic vault error."""


class QuantumVault:
    """
    Encrypted password vault.

    Fernet with PBKDF2-HMAC-SHA256. V1 keys retain hardware binding;
    new v2 keys are portable and derived only from master password + salt.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or VAULT_FILE
        self._fernet: Fernet | None = None
        self._entries: list[VaultEntry] = []
        self._q_salt: bytes | None = None
        self._hardware_binding = None
        self._vault_version: int | None = None

    # ---------- backup helpers ----------

    def _backup_path(self) -> Path:
        """
        Compute a separate, rotated location for the vault backup.

        We keep the backup in a sibling 'backup' directory next to the
        vault file so it is not stored in exactly the same place.
        """
        base_dir = self.path.parent
        backup_dir = base_dir / "backup"
        try:
            backup_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            # Fallback: use the same directory if backup dir cannot be created.
            backup_dir = base_dir
        return backup_dir / (self.path.name + ".bak")

    def backup_to_disk(self) -> None:
        """Atomically snapshot the CURRENT encrypted vault to .bak.

        Called *before* overwriting an existing vault. Backup failure aborts
        the save, preserving the existing recoverable vault.
        """
        if not self.exists():
            return
        bpath = self._backup_path()
        _atomic_write_bytes(bpath, self.path.read_bytes())

    def restore_from_backup(self) -> bool:
        """Explicitly restore the preceding vault generation.

        The backup is structurally validated, but cannot be authenticated
        without its master password/device secret. Preserve the current file
        as a private .corrupt snapshot before replacing it; never destroy an
        earlier .corrupt snapshot.
        """
        bpath = self._backup_path()
        try:
            if not bpath.is_file():
                return False
            data = bpath.read_bytes()
            payload = json.loads(data)
            if not isinstance(payload, dict) or payload.get("version") not in SUPPORTED_VAULT_VERSIONS:
                return False
            if len(base64.b64decode(payload["q_salt"], validate=True)) != 32:
                return False
            if not base64.b64decode(payload["data"], validate=True):
                return False

            if self.path.exists():
                # Use a unique suffix so forensic copies are never overwritten.
                import secrets
                corrupt = self.path.with_name(
                    self.path.name + ".corrupt." + secrets.token_hex(6)
                )
                _atomic_write_bytes(corrupt, self.path.read_bytes())
            _atomic_write_bytes(self.path, data)
            self.lock()  # Require a fresh authenticated unlock after restore.
            return True
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            return False

    # ---------- helpers ----------

    def exists(self) -> bool:
        """Return True if a vault file already exists on disk."""
        return self.path.exists()

    def _generate_q_salt(self) -> bytes:
        """Create a fresh 32-byte salt with the operating-system CSPRNG.

        Existing v1 vaults retain their previously stored salt unchanged.
        """
        return os.urandom(32)

    @staticmethod
    def _now_iso() -> str:
        """
        Current UTC time in ISO format (seconds precision).
        Stored on each vault entry for age / rotation analysis.
        """
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    
    def _derive_key(self, master_password: str, q_salt: bytes) -> bytes:
        """
        Deterministic key derivation from master password and quantum salt,
        additionally bound to this device via HardwareBinding.

        Uses PBKDF2-HMAC-SHA256 with a high iteration count so that
        offline brute-force attacks against the master password are
        significantly more expensive, and augments the salt with a
        device-local secret and system fingerprint.
        """
        # Local import to avoid potential circular imports at module import time.
        from .guard import HardwareBinding

        iterations = KDF_ITERATIONS

        binder = getattr(self, "_hardware_binding", None)
        if binder is None:
            binder = HardwareBinding()
            self._hardware_binding = binder

        bound_salt = binder.bind_salt(q_salt)

        dk = hashlib.pbkdf2_hmac(
            "sha256",
            master_password.encode("utf-8"),
            bound_salt,
            iterations,
            dklen=32,
        )
        return base64.urlsafe_b64encode(dk)

    def _derive_portable_key(self, master_password: str, q_salt: bytes) -> bytes:
        """v2: PBKDF2-HMAC-SHA256, independent of hostname, kernel and device files."""
        if not isinstance(q_salt, bytes) or len(q_salt) != 32:
            raise QuantumVaultError("Invalid portable vault salt.")
        dk = hashlib.pbkdf2_hmac(
            "sha256", master_password.encode("utf-8"),
            b"quantalock:v2:" + q_salt,
            PORTABLE_KDF_ITERATIONS, dklen=32,
        )
        return base64.urlsafe_b64encode(dk)

    def _key_for_version(self, master_password: str, q_salt: bytes, version: int) -> bytes:
        if version == LEGACY_VAULT_VERSION:
            return self._derive_key(master_password, q_salt)
        if version == VAULT_VERSION:
            return self._derive_portable_key(master_password, q_salt)
        raise QuantumVaultError("Unsupported vault version.")

    # ---------- lifecycle ----------

    def initialize(self, master_password: str) -> None:
        """
        First-time setup: create a portable v2 vault with an OS-generated salt.

        If the vault file already exists, this refuses to overwrite it.
        """
        if self.exists():
            raise QuantumVaultError("Vault already exists; cannot initialize.")

        self._q_salt = self._generate_q_salt()
        self._vault_version = VAULT_VERSION
        key = self._key_for_version(master_password, self._q_salt, self._vault_version)
        self._fernet = Fernet(key)
        self._entries = []
        self.save()

    def unlock(self, master_password: str) -> None:
        """
        Unlock the vault by loading the q_salt from disk and deriving the key.

        Raises QuantumVaultError if the file is missing, password is wrong,
        or the file is corrupted.
        """
        if not self.exists():
            raise QuantumVaultError("Vault file not found. Create it first.")

        raw = self.path.read_text(encoding="utf-8")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise QuantumVaultError(
                "Vault file is corrupted or in an old format."
            ) from exc

        version = payload.get("version")
        if type(version) is not int or version not in SUPPORTED_VAULT_VERSIONS:
            raise QuantumVaultError("Unsupported vault version.")

        try:
            q_salt = base64.b64decode(payload["q_salt"])
            ciphertext = base64.b64decode(payload["data"])
        except Exception as exc:  # noqa: BLE001
            raise QuantumVaultError("Vault file is corrupted.") from exc

        key = self._key_for_version(master_password, q_salt, version)
        fernet = Fernet(key)

        try:
            plaintext = fernet.decrypt(ciphertext)
        except InvalidToken as exc:
            raise QuantumVaultError(
                "Invalid master password or corrupted vault."
            ) from exc

        try:
            raw_list = json.loads(plaintext.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise QuantumVaultError("Vault data is corrupted.") from exc
        finally:
            # Best-effort scrubbing of decrypted plaintext from memory.
            if isinstance(plaintext, (bytes, bytearray)):
                try:
                    mutable = bytearray(plaintext)
                    for i in range(len(mutable)):
                        mutable[i] = 0
                    plaintext = bytes(mutable)
                except Exception:
                    # Fallback: at least drop the reference.
                    plaintext = b""
            else:
                plaintext = b""

        self._q_salt = q_salt
        self._fernet = fernet
        self._entries = [VaultEntry(**item) for item in raw_list]
        self._vault_version = version

    def lock(self) -> None:
        """Forget entries and key in memory."""
        self._entries = []
        self._fernet = None
        self._q_salt = None
        self._vault_version = None

    def save(self) -> None:
        """Encrypt current entries and write to disk."""
        if self._fernet is None or self._q_salt is None or self._vault_version is None:
            raise QuantumVaultError("Vault is locked; cannot save.")
        if self._vault_version not in SUPPORTED_VAULT_VERSIONS:
            raise QuantumVaultError("Unsupported vault version.")

        raw_list = [asdict(e) for e in self._entries]
        plaintext = json.dumps(raw_list, indent=2).encode("utf-8")
        ciphertext = self._fernet.encrypt(plaintext)

        payload = {
            "version": self._vault_version,
            "q_salt": base64.b64encode(self._q_salt).decode("ascii"),
            "data": base64.b64encode(ciphertext).decode("ascii"),
        }
        # Preserve the previous good generation before publishing the new one.
        # The old vault remains untouched if either backup or staging fails.
        try:
            if self.exists():
                self.backup_to_disk()
            _atomic_write_bytes(self.path, json.dumps(payload).encode("utf-8"))
        except OSError as exc:
            raise QuantumVaultError("Vault save failed; previous vault preserved.") from exc
        
    def get_header_for_integrity(self) -> dict:
        """
        Return a lightweight, non-sensitive header describing the vault file.

        This is used by IntegrityGuard to detect tampering. It never
        exposes decrypted entries.
        """
        if not self.exists():
            return {}

        try:
            raw = self.path.read_text(encoding="utf-8")
            payload = json.loads(raw)
        except Exception:
            return {}

        return {
            "version": int(payload.get("version", 0)),
            "q_salt": str(payload.get("q_salt", "")),
        }

    # ---------- master password change ----------

    def change_master_password(self, old_password: str, new_password: str) -> None:
        """
        Change the master password safely.

        Steps:
        - Unlock with the old password (validates it and loads entries).
        - Generate a *new* quantum salt.
        - Re-encrypt all entries under the new key.
        """
        if not self.exists():
            raise QuantumVaultError("Vault does not exist yet.")

        # This will raise if old_password is wrong.
        self.unlock(old_password)

        # Re-salt using the OS CSPRNG
        self._q_salt = self._generate_q_salt()
        key = self._key_for_version(new_password, self._q_salt, self._vault_version)
        self._fernet = Fernet(key)

        # Save entries with new key
        self.save()

    # ---------- entries API ----------

    @property
    def entries(self) -> List[VaultEntry]:
        return list(self._entries)

    def add_or_update(self, entry: VaultEntry) -> None:
        """
        Insert or replace by label.

        - Preserve original created_at when updating.
        - Always refresh last_rotated_at when the entry is changed.
        """
        now = self._now_iso()

        for i, existing in enumerate(self._entries):
            if existing.label == entry.label:
                # Keep original creation time if present.
                entry.created_at = getattr(existing, "created_at", "") or now
                # Any change counts as a rotation/update.
                entry.last_rotated_at = now
                self._entries[i] = entry
                return

        # New entry
        entry.created_at = getattr(entry, "created_at", "") or now
        entry.last_rotated_at = now
        self._entries.append(entry)

    def delete(self, label: str) -> None:
        self._entries = [e for e in self._entries if e.label != label]
