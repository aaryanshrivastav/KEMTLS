"""Generic helper utilities shared across the project."""

from __future__ import annotations

import os
import secrets
import string
import time
from typing import Optional


DEFAULT_RANDOM_CHARSET = string.ascii_letters + string.digits + "-_"


def generate_random_string(length: int = 32, charset: Optional[str] = None) -> str:
    """Generate a cryptographically strong random string."""
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("length must be an integer")
    if length < 0:
        raise ValueError("length must be non-negative")
    if charset is None:
        charset = DEFAULT_RANDOM_CHARSET
    if not isinstance(charset, str) or not charset:
        raise ValueError("charset must be a non-empty string")

    return "".join(secrets.choice(charset) for _ in range(length))


def generate_random_bytes(length: int = 32) -> bytes:
    """Generate cryptographically strong random bytes."""
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("length must be an integer")
    if length < 0:
        raise ValueError("length must be non-negative")
    return os.urandom(length)


def get_timestamp() -> int:
    """Return the current Unix timestamp in seconds."""
    return int(time.time())


def is_expired(expiry_timestamp: Optional[int], current_time: Optional[int] = None) -> bool:
    """Return True when the expiry timestamp has passed."""
    if expiry_timestamp is None:
        return False
    if isinstance(expiry_timestamp, bool) or not isinstance(expiry_timestamp, int):
        raise TypeError("expiry_timestamp must be an integer or None")
    if current_time is None:
        current_time = get_timestamp()
    elif isinstance(current_time, bool) or not isinstance(current_time, int):
        raise TypeError("current_time must be an integer when provided")
    return current_time >= expiry_timestamp


def format_token_for_display(token: str, max_length: int = 50) -> str:
    """Truncate a token for display while preserving both ends."""
    if not isinstance(token, str):
        raise TypeError("token must be a string")
    if isinstance(max_length, bool) or not isinstance(max_length, int):
        raise TypeError("max_length must be an integer")
    if max_length < 7:
        raise ValueError("max_length must be at least 7")
    if len(token) <= max_length:
        return token

    prefix_len = max_length // 2 - 2
    suffix_len = max_length // 2 - 1
    return token[:prefix_len] + "..." + token[-suffix_len:]


def validate_session_id(session_id: str) -> bool:
    """Validate the simple session-id format used by the project."""
    if not isinstance(session_id, str):
        return False
    if len(session_id) < 8 or len(session_id) > 128:
        return False
    allowed = set(DEFAULT_RANDOM_CHARSET)
    return all(char in allowed for char in session_id)


__all__ = [
    "DEFAULT_RANDOM_CHARSET",
    "format_token_for_display",
    "generate_random_bytes",
    "generate_random_string",
    "get_timestamp",
    "is_expired",
    "validate_session_id",
]
