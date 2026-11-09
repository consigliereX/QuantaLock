"""Explicit interactive QuantaLock legacy migration, never automatic."""
from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path

from .vault import VAULT_FILE, QuantumVault, QuantumVaultError


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect or explicitly migrate vault v1 to v2")
    parser.add_argument("action", choices=("inspect", "migrate", "rollback"), nargs="?", default="inspect")
    parser.add_argument("--path", type=Path, default=VAULT_FILE, help="encrypted vault path")
    parser.add_argument("--archive", type=Path, help="pre-v2 archive for explicit rollback")
    args = parser.parse_args()
    vault = QuantumVault(args.path)

    if args.action == "inspect":
        try:
            payload = json.loads(vault.path.read_text(encoding="utf-8"))
            version = payload["version"]
            if type(version) is not int or version not in (1, 2):
                raise ValueError("Unsupported vault version")
        except (OSError, ValueError, KeyError, TypeError):
            print("FAIL: Could not inspect vault header")
            return 1
        print(f"PASS: Vault format v{version}; no changes made")
        return 0

    if not __import__("sys").stdin.isatty():
        print("FAIL: Interactive terminal required for migrations")
        return 1

    if args.action == "migrate":
        print("WARNING: Close all other QuantaLock processes and securely back up the v1 vault AND device secret.")
        if input("Type MIGRATE to proceed: ").strip() != "MIGRATE":
            print("CANCELLED: No changes made")
            return 1
        password = getpass.getpass("Existing v1 master password: ")
        try:
            archive = vault.migrate_v1_to_v2(password)
        except (QuantumVaultError, OSError, ValueError) as exc:
            print(f"FAIL: {exc}")
            return 1
        print("PASS: Vault migrated to portable v2 and re-opened successfully")
        print(f"RECOVERY: Preserve encrypted v1 archive at {archive}")
        return 0

    if args.archive is None:
        print("FAIL: Rollback requires --archive")
        return 1
    print("WARNING: Rollback reintroduces kernel/hostname/device-secret dependency.")
    if input("Type RESTORE V1 to proceed: ").strip() != "RESTORE V1":
        print("CANCELLED: No changes made")
        return 1
    password = getpass.getpass("Original v1 master password: ")
    try:
        snapshot = vault.restore_v1_migration_backup(args.archive, password)
    except (QuantumVaultError, OSError, ValueError) as exc:
        print(f"FAIL: {exc}")
        return 1
    print("PASS: Authenticated v1 archive restored")
    print(f"RECOVERY: Previous v2 ciphertext preserved at {snapshot}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
