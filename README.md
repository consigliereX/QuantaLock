# QuantaLock

**Experimental OS-CSPRNG password generator, simulated quantum-circuit demonstration, and encrypted-vault prototype.**

> [!IMPORTANT]
> **Research prototype — not security-audited.** QuantaLock does **not** use a physical quantum random-number generator. Do not rely on it for production secrets or high-value credentials. The password-generation and vault designs require security review and validation.

## What this project does

- Builds and samples quantum circuits using Qiskit Aer's classical simulator.
- XOR-combines simulated bitstreams and mixes the result with SHA-256 for educational metadata only; those bits do not determine the password.
- Uses Python's `secrets.choice` for unbiased password-character selection from a configurable alphabet (8–128 characters per password).
- Provides a Python CLI and PySide6 GUI.
- Stores vault entries encrypted with Fernet, using PBKDF2-HMAC-SHA256 (300,000 iterations) to derive a key from the master password and a device-dependent salt.
- Includes local backups and an integrity manifest for selected source files.

## Security and correctness limitations

1. **Simulation is not quantum entropy.** `qiskit_aer.AerSimulator` simulates quantum circuit behavior in software. It does not obtain randomness from quantum hardware, and its sampling must not be assumed cryptographically secure.
2. **Some circuit outputs are deterministic.** The circuit applies an H gate and then a second H gate to odd-indexed qubits before measurement, yielding predictable zeroes in the ideal circuit. With the default 20-qubit configuration, only 10 positions per stream are nondeterministic in an ideal simulation.
3. **Hashing does not create entropy.** SHA-256 can mix bits but cannot increase the amount of unpredictable information in its input. XORing simulator streams does not establish a cryptographically secure entropy source.
4. **Legacy bit-to-password mapping is not security-safe.** The retained experimental `bits_to_password` helper reduces 8-bit values modulo alphabet length and repeats short bitstreams, but is no longer used by either password-generation entry point. Passwords instead use the operating system CSPRNG through `secrets.choice`. The reported `entropy_bits` remains a theoretical capacity estimate, not an independently audited strength measurement.
5. **Device binding is not a guaranteed security boundary.** Key derivation uses a local device-secret file and coarse system fingerprint. An attacker who can obtain these may reproduce the binding. Conversely, changes in OS/kernel or hostname data, or loss of the device-secret file, may make an existing vault impossible to unlock.
6. **Vault reliability and security have not been independently established.** Preserve backups of the vault *and* its device-secret file before experiments. The current implementation is not recommended for protecting important credentials.
7. **Local integrity checks are not trusted attestation.** A manifest and locally held keys cannot provide strong tamper resistance against an attacker controlling the machine.

## How it works

```text
OS CSPRNG -> unbiased secrets.choice(alphabet) -> password

Separate educational path:
Qiskit Aer simulator -> sample bitstreams -> XOR -> SHA-256
    -> demonstration metadata only (never a password entropy source)

Master password + stored salt + local secret + system fingerprint
    -> PBKDF2-HMAC-SHA256 -> Fernet key
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

## Vault write/recovery behavior

Vault v1 now saves encrypted contents with a same-directory temporary file
and atomic replacement. Before overwriting an existing vault it keeps a
previous-generation encrypted `.bak` copy. Backup failure aborts the save.
Recovery is explicit: `QuantumVault.restore_from_backup()` preserves the
current file as a `.corrupt.*` snapshot and restores the previous generation.
Restoring an older backup may require the master password valid at that time.

**Important:** Existing v1 master-password/device-binding derivation is unchanged.
Keep a separate secure backup of both the vault and `~/.qpgen_device_secret.bin`;
changing kernel/hostname or losing the local device secret may still lock
out an existing vault. Structural backup checks do not prove decryptability.
Do not use this prototype for high-value credentials.

## Engineering priorities

- Completed: the password generation path now uses an operating-system CSPRNG; quantum simulation is retained for demonstration metadata.
- Completed: unbiased character sampling, validated unique-character alphabets, and password length limits (8–128). Continue reviewing the GUI's optional memory-word transformations.
- Redesign vault recovery and device binding to avoid routine OS changes causing lockout.
- Add automated tests, threat-model documentation, and continuous integration.
- Review local file permissions, backup handling, and atomic vault writes before considering real credential storage.

## Project status

**Experimental / research-only.** No claim of quantum-grade security, security certification, or production readiness is made.
