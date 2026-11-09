# QuantaLock

**Experimental password-generation and encrypted-vault prototype using simulated quantum circuits.**

> [!IMPORTANT]
> **Research prototype — not security-audited.** QuantaLock does **not** use a physical quantum random-number generator. Do not rely on it for production secrets or high-value credentials. The password-generation and vault designs require security review and validation.

## What this project does

- Builds and samples quantum circuits using Qiskit Aer's classical simulator.
- XOR-combines simulated bitstreams and mixes the result with SHA-256.
- Maps processed bits into a configurable password alphabet.
- Provides a Python CLI and PySide6 GUI.
- Stores vault entries encrypted with Fernet, using PBKDF2-HMAC-SHA256 (300,000 iterations) to derive a key from the master password and a device-dependent salt.
- Includes local backups and an integrity manifest for selected source files.

## Security and correctness limitations

1. **Simulation is not quantum entropy.** `qiskit_aer.AerSimulator` simulates quantum circuit behavior in software. It does not obtain randomness from quantum hardware, and its sampling must not be assumed cryptographically secure.
2. **Some circuit outputs are deterministic.** The circuit applies an H gate and then a second H gate to odd-indexed qubits before measurement, yielding predictable zeroes in the ideal circuit. With the default 20-qubit configuration, only 10 positions per stream are nondeterministic in an ideal simulation.
3. **Hashing does not create entropy.** SHA-256 can mix bits but cannot increase the amount of unpredictable information in its input. XORing simulator streams does not establish a cryptographically secure entropy source.
4. **Password mapping can bias or repeat outputs.** The implementation reduces 8-bit values modulo the alphabet length, and repeats a bitstream when it is too short. The reported `entropy_bits` is a theoretical alphabet-capacity figure, not a measured security strength.
5. **Device binding is not a guaranteed security boundary.** Key derivation uses a local device-secret file and coarse system fingerprint. An attacker who can obtain these may reproduce the binding. Conversely, changes in OS/kernel or hostname data, or loss of the device-secret file, may make an existing vault impossible to unlock.
6. **Vault reliability and security have not been independently established.** Preserve backups of the vault *and* its device-secret file before experiments. The current implementation is not recommended for protecting important credentials.
7. **Local integrity checks are not trusted attestation.** A manifest and locally held keys cannot provide strong tamper resistance against an attacker controlling the machine.

## How it works

```text
Qiskit Aer circuit simulator
    -> sample bitstreams -> XOR -> SHA-256 mixing
    -> 8-bit chunks -> alphabet mapping -> candidate password

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
  cli.py              CLI and generation pipeline
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

## Engineering priorities

- Replace simulator output in the real password generator with an operating-system cryptographically secure random-number generator (CSPRNG); keep quantum-circuit simulation as a separate educational feature.
- Use unbiased alphabet sampling, explicit validation, and safe length limits.
- Redesign vault recovery and device binding to avoid routine OS changes causing lockout.
- Add automated tests, threat-model documentation, and continuous integration.
- Review local file permissions, backup handling, and atomic vault writes before considering real credential storage.

## Project status

**Experimental / research-only.** No claim of quantum-grade security, security certification, or production readiness is made.
