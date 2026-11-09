"""Small, Qt-free safety helpers for the QuantaLock GUI."""
from __future__ import annotations

import hashlib
import hmac

MAX_MEMORY_WORD = 32


def compose_password(random_component: str, memory_word: str) -> str:
    """Preserve every random character; append optional user-provided text.

    The caller must generate ``random_component`` with the OS CSPRNG.
    User text is not counted toward the random component's entropy.
    """
    if not isinstance(random_component, str) or not random_component:
        raise ValueError("Random component is required")
    if not isinstance(memory_word, str):
        raise ValueError("Memory word must be text")
    normalized = "".join(c for c in memory_word.strip() if not c.isspace())
    if len(normalized) > MAX_MEMORY_WORD:
        raise ValueError("Memory word must contain no more than 32 characters")
    if not all(c.isprintable() for c in normalized):
        raise ValueError("Memory word cannot contain control characters")
    return random_component + normalized


def clipboard_fingerprint(text: str) -> bytes:
    """In-process ownership marker, not encryption or a secret storage API."""
    if not text:
        raise ValueError("Cannot track empty clipboard text")
    return hashlib.sha256(text.encode("utf-8")).digest()


def clipboard_matches(fingerprint: bytes | None, current_text: str) -> bool:
    """Whether the clipboard still holds the copied value tracked by us."""
    return bool(fingerprint and current_text) and hmac.compare_digest(
        fingerprint, clipboard_fingerprint(current_text)
    )
