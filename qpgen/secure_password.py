"""Unbiased, OS-CSPRNG-backed password generation.

This module never consumes output from Qiskit's software simulator.
"""
from __future__ import annotations

import secrets
from typing import Protocol


class PasswordSettings(Protocol):
    password_length: int
    alphabet: str


def validate_password_config(config: PasswordSettings) -> None:
    length = config.password_length
    alphabet = config.alphabet
    if type(length) is not int or not 8 <= length <= 128:
        raise ValueError("password_length must be an integer from 8 through 128")
    if not isinstance(alphabet, str) or not 2 <= len(alphabet) <= 1024:
        raise ValueError("alphabet must contain between 2 and 1024 characters")
    if len(set(alphabet)) != len(alphabet):
        raise ValueError("alphabet must not contain duplicate characters")


def secure_password(config: PasswordSettings) -> str:
    """Generate independent, uniformly selected characters using secrets.choice."""
    validate_password_config(config)
    return "".join(secrets.choice(config.alphabet) for _ in range(config.password_length))
