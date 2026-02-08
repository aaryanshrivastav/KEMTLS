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
    generate_random_string,
    get_timestamp,
    is_expired,
    create_jwk_from_dilithium_pubkey,
    extract_pubkey_from_jwk
)

__all__ = [
    "base64url_encode",
    "base64url_decode",
    "serialize_message",
    "deserialize_message",
    "generate_random_string",
    "get_timestamp",
    "is_expired",
    "create_jwk_from_dilithium_pubkey",
    "extract_pubkey_from_jwk",
]