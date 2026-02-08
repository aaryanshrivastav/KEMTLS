"""
Message Serialization

This module provides JSON-based serialization for protocol messages.
All messages are serialized to JSON for transmission over the KEMTLS channel.

Usage:
    >>> from utils.serialization import serialize_message, deserialize_message
    >>> 
    >>> message = {'type': 'ServerHello', 'session_id': 'abc123'}
    >>> serialized = serialize_message(message)
    >>> recovered = deserialize_message(serialized)
    >>> assert recovered == message
"""

import json
from typing import Any, Dict


def serialize_message(message: Dict[str, Any]) -> bytes:
    """
    Serialize a message dictionary to JSON bytes.
    
    Args:
        message (dict): Message to serialize
    
    Returns:
        bytes: JSON-encoded message
    
    Example:
        >>> msg = {'type': 'test', 'data': 'hello'}
        >>> serialized = serialize_message(msg)
        >>> isinstance(serialized, bytes)
        True
    """
    if not isinstance(message, dict):
        raise TypeError("Message must be a dictionary")
    
    try:
        # Convert to JSON with sorted keys for deterministic serialization
        json_str = json.dumps(message, sort_keys=True, separators=(',', ':'))
        return json_str.encode('utf-8')
    except Exception as e:
        raise ValueError(f"Failed to serialize message: {e}")


def deserialize_message(data: bytes) -> Dict[str, Any]:
    """
    Deserialize JSON bytes to a message dictionary.
    
    Args:
        data (bytes): JSON-encoded message
    
    Returns:
        dict: Deserialized message
    
    Raises:
        ValueError: If data is not valid JSON
    
    Example:
        >>> data = b'{"type":"test","data":"hello"}'
        >>> msg = deserialize_message(data)
        >>> msg['type']
        'test'
    """
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")
    
    try:
        json_str = data.decode('utf-8')
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON data: {e}")
    except Exception as e:
        raise ValueError(f"Failed to deserialize message: {e}")


def test_serialization():
    """Test message serialization."""
    print("Testing message serialization...")
    
    # Test cases
    test_messages = [
        {'type': 'ServerHello', 'session_id': 'abc123'},
        {'type': 'ClientKeyExchange', 'data': [1, 2, 3]},
        {'nested': {'key': 'value', 'number': 42}},
        {},
        {'unicode': '你好世界'},
    ]
    
    for msg in test_messages:
        # Serialize
        serialized = serialize_message(msg)
        assert isinstance(serialized, bytes)
        
        # Deserialize
        recovered = deserialize_message(serialized)
        assert recovered == msg
        
        print(f"  ✓ {str(msg)[:60]}{'...' if len(str(msg)) > 60 else ''}")
    
    # Test deterministic serialization
    msg = {'z': 3, 'a': 1, 'b': 2}
    s1 = serialize_message(msg)
    s2 = serialize_message(msg)
    assert s1 == s2
    print("  ✓ Deterministic serialization")
    
    print("\n✅ Message serialization test passed!")


if __name__ == "__main__":
    test_serialization()