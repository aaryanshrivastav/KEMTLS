"""
Message Serialization

This module provides JSON-based serialization for protocol messages.
All messages are serialized to JSON for transmission over the KEMTLS channel.
Canonical encoding is enforced for deterministic output (required for signing/hashing).
Binary-safe handling of 'bytes' is provided by automatic Base64url encoding.

Usage:
    >>> from utils.serialization import serialize_message, deserialize_message
    >>> 
    >>> message = {'type': 'ServerHello', 'public_key': b'\\x01\\x02\\x03'}
    >>> serialized = serialize_message(message)
    >>> recovered = deserialize_message(serialized)
    >>> assert recovered['public_key'] == 'AQID'  # base64url-encoded

Tests:
    Run "pytest tests/test_serialization.py" to run the tests.
"""

import json
from typing import Any, Dict
from .encoding import base64url_encode
from rust_ext import serialization as rust_serialization

__all__ = ["serialize_message", "deserialize_message", "CanonicalJSONEncoder"]


class CanonicalJSONEncoder(json.JSONEncoder):
    """
    Strict JSON encoder for canonical, binary-safe serialization.
    - Automatically encodes 'bytes' using Base64url.
    - Enforces deterministic output (sorted keys, no whitespace).
    - Disallows invalid JSON values (NaN, Infinity).
    """
    
    def __init__(self, *args, **kwargs):
        # Override with canonical defaults
        kwargs['sort_keys'] = True
        kwargs['separators'] = (',', ':')
        kwargs['allow_nan'] = False
        super().__init__(*args, **kwargs)

    def default(self, obj: Any) -> Any:
        if isinstance(obj, bytes):
            return base64url_encode(obj)
        # Fallback to standard encoder (will raise TypeError for other non-serializable types)
        return super().default(obj)


def serialize_message(message: Dict[str, Any]) -> bytes:
    """
    Serialize a message dictionary to deterministic JSON bytes.
    
    Args:
        message (dict): Message to serialize (can contain bytes)
    
    Returns:
        bytes: Canonical JSON-encoded message (UTF-8)
    
    Raises:
        ValueError: If serialization fails (e.g., contains NaN/Inf or unknown types)
        TypeError: If message is not a dictionary
    
    Example:
        >>> msg = {'key': b'\\x00'}
        >>> serialize_message(msg)
        b'{"key":"AA"}'
    """
    if not isinstance(message, dict):
        raise TypeError("Message must be a dictionary")
    
    try:
        return rust_serialization.canonical_json_encode(
            message,
            fallback=_serialize_message_python,
        )
    except (ValueError, TypeError) as e:
        raise ValueError(f"Failed to serialize message: {e}")


def deserialize_message(data: bytes) -> Dict[str, Any]:
    """
    Deserialize JSON bytes to a message dictionary.
    
    Notes:
        Binary data will remain as base64url-encoded strings. 
        It is the caller's responsibility to decode them back to bytes.
    
    Args:
        data (bytes): JSON-encoded message
    
    Returns:
        dict: Deserialized message
    
    Raises:
        ValueError: If data is not valid JSON
        TypeError: If data is not bytes
    """
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")
    
    try:
        return rust_serialization.canonical_json_decode(
            data,
            fallback=_deserialize_message_python,
        )
    except (ValueError, UnicodeDecodeError) as e:
        message = str(e)
        if message.startswith("Invalid JSON data"):
            raise ValueError(message)
        raise ValueError(f"Failed to deserialize message: {e}")


def _serialize_message_python(message: Dict[str, Any]) -> bytes:
    json_str = json.dumps(message, cls=CanonicalJSONEncoder)
    return json_str.encode('utf-8')


def _deserialize_message_python(data: bytes) -> Dict[str, Any]:
    try:
        json_str = data.decode('utf-8')
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON data: {e}")