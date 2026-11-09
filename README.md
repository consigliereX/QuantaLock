# QuantaLock

**Experimental OS-CSPRNG password generator, simulated quantum-circuit demonstration, and encrypted-vault prototype.**

> [!IMPORTANT]
> **Research prototype — not security-audited.** QuantaLock does **not** use a physical quantum random-number generator. Do not rely on it for production secrets or high-value credentials. The password-generation and vault designs require security review and validation.

## What this project does

- Builds and samples quantum circuits using Qiskit Aer's classical simulator.
- XOR-combines simulated bitstreams and mixes the result with SHA-256 for educational metadata only; those bits do not determine the password.
- Uses Python's `secrets.choice` for unbiased password-character selection from a configurable alphabet (8–128 characters per password).
- Provides a Python CLI and PySide6 GUI.
- Stores entries encrypted with Fernet: new portable v2 vaults use PBKDF2-HMAC-SHA256 (600,000 iterations); legacy device-bound v1 vaults remain readable with their existing 300,000-iteration KDF.
- Includes local backups and an integrity manifest for selected source files.

## Security and correctness limitations

1. **Simulation is not quantum entropy.** `qiskit_aer.AerSimulator` simulates quantum circuit behavior in software. It does not obtain randomness from quantum hardware, and its sampling must not be assumed cryptographically secure.
2. **Some circuit outputs are deterministic.** The circuit applies an H gate and then a second H gate to odd-indexed qubits before measurement, yielding predictable zeroes in the ideal circuit. With the default 20-qubit configuration, only 10 positions per stream are nondeterministic in an ideal simulation.
3. **Hashing does not create entropy.** SHA-256 can mix bits but cannot increase the amount of unpredictable information in its input. XORing simulator streams does not establish a cryptographically secure entropy source.
4. **Legacy bit-to-password mapping is not security-safe.** The retained experimental `bits_to_password` helper reduces 8-bit values modulo alphabet length and repeats short bitstreams, but is no longer used by either password-generation entry point. Passwords instead use the operating system CSPRNG through `secrets.choice`. The reported `entropy_bits` remains a theoretical capacity estimate, not an independently audited strength measurement.
5. **Legacy v1 device binding risks lockout.** Old vaults require a local device-secret file and coarse system fingerprint. Changes in OS/kernel or hostname data, or loss of the secret, may make v1 impossible to unlock. New v2 vaults avoid this binding, but existing v1 vaults are not automatically converted.
6. **Vault reliability and security have not been independently established.** Preserve backups of the vault *and* its device-secret file before experiments. The current implementation is not recommended for protecting important credentials.
7. **Local integrity checks are not trusted attestation.** A manifest and locally held keys cannot provide strong tamper resistance against an attacker controlling the machine.

## How it works

```text
OS CSPRNG -> unbiased secrets.choice(alphabet) -> password

Separate educational path:
Qiskit Aer simulator -> sample bitstreams -> XOR -> SHA-256
    -> demonstration metadata only (never a password entropy source)

New v2: master password + stored random salt -> PBKDF2 -> Fernet key
Legacy v1: master + salt + device secret + system fingerprint -> PBKDF2
    -> encrypted local vault
```

## Project layout

```text
qpgen/
  quantum_engine.py   Qiskit Aer circuit simulation
  entropy.py          SHA-256 processing
  mapping.py          Password alphabet mapping
  config.py           Generator settings
  cli.py              CLI and optional simulator metadata pipeline
  secure_password.py  OS-CSPRNG-backed password generation
  gui_qt.py           GUI
  vault.py            Vault persistence and cryptography
  guard.py            Device binding and local integrity checks
run_qpgen.py          CLI entry point
run_qpgen_gui.py      GUI entry point
requirements.txt      Python dependencies
```

## Local setup

Python 3.11+ is the intended runtime. The dependency list includes Qiskit, Qiskit Aer, cryptography, and PySide6. Compatibility across platforms has not been independently verified.

```bash
git clone https://github.com/consigliereX/QuantaLock.git
cd QuantaLock
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python run_qpgen.py
```

To launch the GUI: `python run_qpgen_gui.py`.

## Vault versions and recovery

- **v2 (new vaults):** Fernet + PBKDF2-HMAC-SHA256, 600,000 iterations,
  OS-CSPRNG 32-byte salt. The key depends on the master password and stored
  salt, **not** on the kernel, hostname, or device-secret file. This improves
  portability, but protecting the master password and encrypted backup remains
  essential. PBKDF2 is not memory-hard; this prototype is not audited.
- **v1 (legacy):** Existing encrypted vaults still unlock using the unchanged
  300,000-iteration, device-bound KDF. Saving or changing the master password
  on a v1 file **keeps it v1**. The original device-secret file and system
  fingerprint are still required. No automatic migration is attempted.
- **Migration:** Explicit authenticated v1-to-v2 migration is available through
  `python -m qpgen.migrate_vault migrate`. It creates a uniquely named,
  encrypted `pre-v2` recovery archive before replacing the live vault, and
  verifies the new v2 file by reopening it. No automatic migration occurs.
  Preserve the original v1 device secret and environment for rollback.

Both formats retain M2 atomic writes, a previous-generation encrypted `.bak`
file, and explicit `restore_from_backup()`. Structural backup checks cannot
prove decryptability. Restoration of v1 needs the historical binding context.
Do not use this prototype for important credentials.

## Explicit v1-to-v2 migration (optional)

**Close the GUI before proceeding.** Migrations are manual and only needed
for older v1 vaults; new v2 vaults do not require them. First inspect the
version without entering a password:

```bash
python -m qpgen.migrate_vault inspect
```

If your vault is **v1**, make separate secure backups of the encrypted vault
and `~/.qpgen_device_secret.bin` while its original OS fingerprint is still
available. Then run:

```bash
python -m qpgen.migrate_vault migrate
```

The command requests explicit confirmation and the **existing** master
password via a hidden prompt. It preserves the old v1 ciphertext in a unique
`.pre-v2-*.bak` file beside the vault and verifies the new portable v2 file.
It never prints vault entries, master passwords, or ciphertext.

Manual rollback, only if needed (with the **old** v1 master password and
original device-binding context):

```bash
python -m qpgen.migrate_vault rollback --archive /path/to/quantum_vault.bin.pre-v2-....bak
```

Rollback authenticates the archive before modifying the live vault and
preserves the current v2 ciphertext in a separate `.pre-rollback-v2-*.bak`.
Migration/rollback are not safe while a second process has the vault open.
Retain independent backups; the adjacent recovery archive is not an offsite
backup. Do not run this experimental process on irreplaceable credentials.

## M5: Local integrity monitor (advisory only)

The source-file and vault-header hash comparison uses a locally writable
manifest. It is **not cryptographic attestation** or protection against a
hostile process with access to the same machine. A missing manifest seeds a
new, untrusted baseline; a matching baseline is only a local consistency check.

Code and vault files are **never automatically restored** after a mismatch.
On an unlock-time mismatch the GUI warns the user and requires explicit
confirmation before attempting normal authenticated decryption. An unexpected
change should be investigated by reinstalling code from a verified source.
Live monitoring locks the vault on a newly detected mismatch, but offers no
automatic restore. Accepting an existing mismatch disables repeated baseline
polling for that session (the baseline is already known to have drifted) and
leaves a visible alert. The next unlock requires new consent. Use the separate
explicit vault recovery/migration workflow
for encrypted vault recovery. Local code-backup restore is disabled; old code
backup artifacts are not deleted by this change.

The guard does not establish trust in code, prevent malware or exfiltration,
validate repository signatures, or independently authenticate the vault.

## GUI generation and clipboard behavior

The GUI's optional memory word is appended to the **complete**
OS-CSPRNG-generated character sequence instead of replacing random characters.
The configured length represents the *random component*; a memory word adds
up to 32 more characters. Password strength shown immediately after generation
counts only the uniform random component and never credits the user word.
Long combined passwords may not be accepted by every external service.

Clipboard auto-clear compares the current clipboard with a fingerprint of the
password the application last copied; unrelated clipboard text is left alone.
This does **not** remove copies retained by clipboard history, OS integration,
other applications or screenshots. Do not use sensitive credentials with an
untrusted desktop/clipboard manager.

## Engineering priorities

- Completed: the password generation path now uses an operating-system CSPRNG; quantum simulation is retained for demonstration metadata.
- Completed: unbiased character sampling, validated unique-character alphabets, and password length limits (8–128). Continue reviewing the GUI's optional memory-word transformations.
- Completed: explicit authenticated v1-to-v2 migration and rollback with standalone encrypted recovery archives; keep testing on synthetic vaults.
- Add independent threat-model documentation, CI, and integration tests beyond the local integrity monitor.
- Review local file permissions, backup handling, and atomic vault writes before considering real credential storage.

## Project status

**Experimental / research-only.** No claim of quantum-grade security, security certification, or production readiness is made.
