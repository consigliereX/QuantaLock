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
- **Migration:** An explicit, authenticated and independently backed-up v1-to-v2
  migration is planned but **not** performed by this patch. Preserve copies of
  the v1 vault and `~/.qpgen_device_secret.bin` before any OS change.

Both formats retain M2 atomic writes, a previous-generation encrypted `.bak`
file, and explicit `restore_from_backup()`. Structural backup checks cannot
prove decryptability. Restoration of v1 needs the historical binding context.
Do not use this prototype for important credentials.

## Engineering priorities

- Completed: the password generation path now uses an operating-system CSPRNG; quantum simulation is retained for demonstration metadata.
- Completed: unbiased character sampling, validated unique-character alphabets, and password length limits (8–128). Continue reviewing the GUI's optional memory-word transformations.
- Complete explicit authenticated migration from legacy device-bound v1 to portable v2, including full rollback and recovery validation.
- Add automated tests, threat-model documentation, and continuous integration.
- Review local file permissions, backup handling, and atomic vault writes before considering real credential storage.

## Project status

**Experimental / research-only.** No claim of quantum-grade security, security certification, or production readiness is made.
