"""
Command-line interface and high-level generator function.
"""
from __future__ import annotations
from dataclasses import dataclass
import math 
from .config import QuantumPassConfig, DEFAULT_CONFIG
from .entropy import amplify_entropy
from .secure_password import secure_password, validate_password_config

@dataclass
class QuantumGenerationMeta:
    """
    Full result of one quantum password generation.
    """
    # Final password
    password: str

    # Mixed / combined bitstreams
    raw_bits: list[int]
    amplified_bits: list[int]

    # Per-qubit measurement basis for the combined stream ("Z"/"X")
    measurement_basis: list[str]

    # Quantum stream details
    streams_raw_bits: list[list[int]]  # raw bits from each independent stream
    streams_used: int                  # how many streams were mixed

    # Strength / config metadata
    entropy_bits: float
    config: QuantumPassConfig

def generate_password_with_meta(
    config: QuantumPassConfig | None = None,
) -> QuantumGenerationMeta:
    """
    High-level generation pipeline with metadata:

    - Sample one or more quantum streams.
    - XOR-combine them into a single raw bitstring.
    - Amplify/mix with SHA-256 (entropy_rounds).
    - Map to password characters.
    """
    cfg = config or DEFAULT_CONFIG
    validate_password_config(cfg)
    from .quantum_engine import QuantumEngine  # optional educational simulation

    # --- quantum sampling: multiple streams ---
    streams_raw_bits: list[list[int]] = []
    combined_bits: list[int] | None = None
    measurement_basis: list[str] | None = None

    streams = max(1, cfg.quantum_streams)

    for _ in range(streams):
        engine = QuantumEngine(cfg)
        bits, basis, _circuit = engine.get_raw_bits_with_meta()

        if combined_bits is None:
            # First stream: just copy
            combined_bits = bits[:]
            measurement_basis = basis[:]  # basis pattern is same for all
        else:
            # Subsequent streams: XOR bit-by-bit into the combined result
            if len(bits) != len(combined_bits):
                raise ValueError(
                    "Quantum streams produced different bit-lengths; "
                    "this should not happen."
                )
            combined_bits = [
                (b ^ c) for b, c in zip(bits, combined_bits)
            ]

        streams_raw_bits.append(bits)

    assert combined_bits is not None
    assert measurement_basis is not None

    # --- entropy amplification ---
    amplified_bits = amplify_entropy(combined_bits, cfg.entropy_rounds)

    # --- map to password ---
    password = secure_password(cfg)  # simulation is metadata, not an entropy source

    # --- theoretical entropy estimate (per password) ---
    if cfg.alphabet:
        entropy_bits = len(password) * math.log2(len(cfg.alphabet))
    else:
        entropy_bits = 0.0

    return QuantumGenerationMeta(
        password=password,
        raw_bits=combined_bits,
        amplified_bits=amplified_bits,
        measurement_basis=measurement_basis,
        streams_raw_bits=streams_raw_bits,
        streams_used=streams,
        entropy_bits=entropy_bits,
        config=cfg,
    )

def generate_password(
    config: QuantumPassConfig | None = None,
) -> str:
    """Create a password using the OS CSPRNG, without running the simulator."""
    return secure_password(config or DEFAULT_CONFIG)

def main() -> None:
    """
    Entry point for `python -m qpgen.cli` or `run_qpgen.py`.
    """
    password = generate_password()
    print("\n[QuantaLock Secure Password Generator]")
    print(f"Generated password: {password}\n")
