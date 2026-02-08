"""
Base64url Encoding/Decoding

This module provides Base64url encoding and decoding functions as specified
in RFC 4648. Base64url is used in JWTs and other web-safe contexts where
standard Base64's '+' and '/' characters would cause issues in URLs.

Base64url replaces:
    '+' → '-'
    '/' → '_'
    '=' padding is removed

Usage:
    >>> from utils.encoding import base64url_encode, base64url_decode
    >>> 
    >>> data = b"Hello, World!"
    >>> encoded = base64url_encode(data)
    >>> decoded = base64url_decode(encoded)
    >>> assert decoded == data
"""

import base64


def base64url_encode(data: bytes) -> str:
    """
    Encode bytes to Base64url string.
    
    Performs standard Base64 encoding, then:
    1. Replace '+' with '-'
    2. Replace '/' with '_'
    3. Remove '=' padding
    
    Args:
        data (bytes): Binary data to encode
    
    Returns:
        str: Base64url-encoded string
    
    Example:
        >>> base64url_encode(b"Hello")
        'SGVsbG8'
        >>> base64url_encode(b"\x00\x01\x02")
        'AAEC'
    """
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")
    
    # Standard Base64 encoding
    encoded = base64.urlsafe_b64encode(data)
    
    # Remove padding
    return encoded.rstrip(b'=').decode('ascii')


def base64url_decode(encoded: str) -> bytes:
    """
    Decode Base64url string to bytes.
    
    Performs the reverse of base64url_encode:
    1. Add padding if needed
    2. Replace '-' with '+'
    3. Replace '_' with '/'
    4. Decode using standard Base64
    
    Args:
        encoded (str): Base64url-encoded string
    
    Returns:
        bytes: Decoded binary data
    
    Raises:
        ValueError: If encoded string is invalid
    
    Example:
        >>> base64url_decode('SGVsbG8')
        b'Hello'
        >>> base64url_decode('AAEC')
        b'\\x00\\x01\\x02'
    """
    if not isinstance(encoded, str):
        raise TypeError("Encoded data must be string")
    
    # Convert to bytes if needed
    if isinstance(encoded, str):
        encoded = encoded.encode('ascii')
    
    # Add padding
    padding_needed = (4 - len(encoded) % 4) % 4
    encoded += b'=' * padding_needed
    
    # Decode
    try:
        return base64.urlsafe_b64decode(encoded)
    except Exception as e:
        raise ValueError(f"Invalid Base64url encoding: {e}")


def test_encoding():
    """Test Base64url encoding/decoding."""
    print("Testing Base64url encoding...")
    
    # Test basic encoding/decoding
    test_cases = [
        b"Hello, World!",
        b"",
        b"\x00\x01\x02\x03\x04",
        b"A" * 100,
        b"The quick brown fox jumps over the lazy dog",
    ]
    
    for data in test_cases:
        encoded = base64url_encode(data)
        decoded = base64url_decode(encoded)
        assert decoded == data, f"Mismatch for {data}"
        # Verify no padding or unsafe characters
        assert '=' not in encoded
        assert '+' not in encoded
        assert '/' not in encoded
        print(f"  ✓ {len(data)} bytes: {encoded[:50]}{'...' if len(encoded) > 50 else ''}")
    
    print("\n✅ Base64url encoding test passed!")


if __name__ == "__main__":
    test_encoding()