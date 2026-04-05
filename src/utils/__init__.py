"""
Utility Functions

This module provides common utility functions used throughout the
KEMTLS-OIDC implementation.

Modules:
    - encoding: Base64url encoding/decoding
    - serialization: Message serialization/deserialization
    - helpers: General helper functions
"""

from .encoding import base64url_encode, base64url_decode
from .serialization import serialize_message, deserialize_message
from .helpers import (
    format_token_for_display,
    generate_random_bytes,
    generate_random_string,
    get_timestamp,
    is_expired,
    validate_session_id,
)

__all__ = [
    "base64url_encode",
    "base64url_decode",
    "serialize_message",
    "deserialize_message",
    "format_token_for_display",
    "generate_random_bytes",
    "generate_random_string",
    "get_timestamp",
    "is_expired",
    "validate_session_id",
]
