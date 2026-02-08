"""
Helper Functions

This module provides various helper functions used throughout the
KEMTLS-OIDC implementation.

Functions:
    - generate_random_string: Generate random alphanumeric strings
    - get_timestamp: Get current Unix timestamp
    - is_expired: Check if a timestamp has expired
    - create_jwk_from_dilithium_pubkey: Create JWK from Dilithium public key
    - extract_pubkey_from_jwk: Extract public key from JWK
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import time
import string
import secrets
from typing import Optional, Dict, Any
# Fix relative import for direct execution
try:
    from utils.encoding import base64url_encode, base64url_decode
except ImportError:
    # Fallback if run from different location
    try:
        from utils.encoding import base64url_encode, base64url_decode
    except ImportError:
        # Ultimate fallback - inline functions
        import base64
        
        def base64url_encode(data: bytes) -> str:
            encoded = base64.urlsafe_b64encode(data)
            return encoded.rstrip(b'=').decode('ascii')
        
        def base64url_decode(encoded: str) -> bytes:
            encoded_bytes = encoded.encode('ascii')
            padding_needed = (4 - len(encoded_bytes) % 4) % 4
            encoded_bytes += b'=' * padding_needed
            return base64.urlsafe_b64decode(encoded_bytes)


def generate_random_string(length: int = 32, charset: str = None) -> str:
    """
    Generate a cryptographically secure random string.
    
    Args:
        length (int): Length of the string (default: 32)
        charset (str, optional): Character set to use
                                Default: alphanumeric + hyphen + underscore
    
    Returns:
        str: Random string
    
    Example:
        >>> random_str = generate_random_string(16)
        >>> len(random_str) == 16
        True
    """
    if charset is None:
        # URL-safe characters
        charset = string.ascii_letters + string.digits + '-_'
    
    return ''.join(secrets.choice(charset) for _ in range(length))


def generate_random_bytes(length: int = 32) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Args:
        length (int): Number of bytes (default: 32)
    
    Returns:
        bytes: Random bytes
    
    Example:
        >>> random_bytes = generate_random_bytes(16)
        >>> len(random_bytes) == 16
        True
    """
    return os.urandom(length)


def get_timestamp() -> int:
    """
    Get current Unix timestamp (seconds since epoch).
    
    Returns:
        int: Current timestamp
    
    Example:
        >>> ts = get_timestamp()
        >>> ts > 0
        True
    """
    return int(time.time())


def is_expired(expiry_timestamp: Optional[int], current_time: Optional[int] = None) -> bool:
    """
    Check if a timestamp has expired.
    
    Args:
        expiry_timestamp (int, optional): Expiration timestamp
        current_time (int, optional): Current time (default: now)
    
    Returns:
        bool: True if expired, False otherwise
    
    Example:
        >>> # Not expired (far future)
        >>> is_expired(get_timestamp() + 3600)
        False
        >>> # Expired (past)
        >>> is_expired(get_timestamp() - 1)
        True
    """
    if expiry_timestamp is None:
        return False
    
    if current_time is None:
        current_time = get_timestamp()
    
    return current_time >= expiry_timestamp


def create_jwk_from_dilithium_pubkey(
    public_key: bytes,
    kid: Optional[str] = None
) -> Dict[str, str]:
    """
    Create a JWK (JSON Web Key) from a Dilithium public key.
    
    This is used for the 'cnf' (confirmation) claim in ID tokens to bind
    the token to a client's cryptographic key.
    
    Args:
        public_key (bytes): Dilithium3 public key (1952 bytes)
        kid (str, optional): Key ID
    
    Returns:
        dict: JWK representation
    
    Example:
        >>> from crypto.dilithium_sig import DilithiumSignature
        >>> sig = DilithiumSignature()
        >>> pk, sk = sig.generate_keypair()
        >>> jwk = create_jwk_from_dilithium_pubkey(pk, "client-key-1")
        >>> jwk['kty'] == 'LWE'
        True
    """
    jwk = {
        "kty": "LWE",  # Key Type: Lattice-based (Learning With Errors)
        "alg": "DILITHIUM3",
        "use": "sig",  # Public key use: signature
        "x": base64url_encode(public_key),
    }
    
    if kid:
        jwk["kid"] = kid
    
    return jwk


def extract_pubkey_from_jwk(jwk: Dict[str, str]) -> bytes:
    """
    Extract Dilithium public key from a JWK.
    
    Args:
        jwk (dict): JWK containing Dilithium public key
    
    Returns:
        bytes: Dilithium3 public key
    
    Raises:
        ValueError: If JWK is invalid or missing required fields
    
    Example:
        >>> from crypto.dilithium_sig import DilithiumSignature
        >>> sig = DilithiumSignature()
        >>> pk, sk = sig.generate_keypair()
        >>> jwk = create_jwk_from_dilithium_pubkey(pk)
        >>> recovered_pk = extract_pubkey_from_jwk(jwk)
        >>> recovered_pk == pk
        True
    """
    # Validate JWK
    if not isinstance(jwk, dict):
        raise ValueError("JWK must be a dictionary")
    
    if jwk.get('kty') != 'LWE':
        raise ValueError(f"Invalid key type: expected 'LWE', got '{jwk.get('kty')}'")
    
    if jwk.get('alg') != 'DILITHIUM3':
        raise ValueError(f"Invalid algorithm: expected 'DILITHIUM3', got '{jwk.get('alg')}'")
    
    if 'x' not in jwk:
        raise ValueError("JWK missing 'x' field (public key)")
    
    # Decode public key
    try:
        public_key = base64url_decode(jwk['x'])
    except Exception as e:
        raise ValueError(f"Failed to decode public key: {e}")
    
    # Validate size
    if len(public_key) != 1952:  # Dilithium3 public key size
        raise ValueError(
            f"Invalid public key size: expected 1952 bytes, got {len(public_key)}"
        )
    
    return public_key


def format_token_for_display(token: str, max_length: int = 50) -> str:
    """
    Format a token for display (truncate if too long).
    
    Args:
        token (str): Token string
        max_length (int): Maximum display length
    
    Returns:
        str: Formatted token
    
    Example:
        >>> format_token_for_display("verylongtoken" * 10, 20)
        'verylongtoken...token'
    """
    if len(token) <= max_length:
        return token
    
    prefix_len = max_length // 2 - 2
    suffix_len = max_length // 2 - 1
    
    return token[:prefix_len] + "..." + token[-suffix_len:]


def validate_session_id(session_id: str) -> bool:
    """
    Validate a session ID format.
    
    Args:
        session_id (str): Session ID to validate
    
    Returns:
        bool: True if valid, False otherwise
    """
    if not isinstance(session_id, str):
        return False
    
    if len(session_id) < 8 or len(session_id) > 128:
        return False
    
    # Allow alphanumeric, hyphen, underscore
    allowed = set(string.ascii_letters + string.digits + '-_')
    return all(c in allowed for c in session_id)


def test_helpers():
    """Test helper functions."""
    print("Testing helper functions...")
    
    # Test random string generation
    print("  Testing random string generation...")
    random_str = generate_random_string(32)
    assert len(random_str) == 32
    random_str2 = generate_random_string(32)
    assert random_str != random_str2  # Should be different
    print(f"  ✓ Random string: {random_str}")
    
    # Test random bytes
    print("  Testing random bytes...")
    random_bytes = generate_random_bytes(16)
    assert len(random_bytes) == 16
    print(f"  ✓ Random bytes: {random_bytes.hex()}")
    
    # Test timestamp
    print("  Testing timestamp...")
    ts = get_timestamp()
    assert ts > 0
    print(f"  ✓ Timestamp: {ts}")
    
    # Test expiration check
    print("  Testing expiration...")
    assert not is_expired(ts + 3600)  # Future
    assert is_expired(ts - 1)  # Past
    assert not is_expired(None)  # No expiry
    print("  ✓ Expiration check works")
    
    # Test JWK creation/extraction
    print("  Testing JWK creation...")
    from crypto.dilithium_sig import DilithiumSignature
    sig = DilithiumSignature()
    pk, sk = sig.generate_keypair()
    
    jwk = create_jwk_from_dilithium_pubkey(pk, "test-key")
    assert jwk['kty'] == 'LWE'
    assert jwk['alg'] == 'DILITHIUM3'
    assert jwk['kid'] == 'test-key'
    print("  ✓ JWK created")
    
    recovered_pk = extract_pubkey_from_jwk(jwk)
    assert recovered_pk == pk
    print("  ✓ Public key extracted from JWK")
    
    # Test token formatting
    print("  Testing token formatting...")
    long_token = "a" * 100
    formatted = format_token_for_display(long_token, 20)
    assert len(formatted) == 20
    print(f"  ✓ Formatted token: {formatted}")
    
    # Test session ID validation
    print("  Testing session ID validation...")
    assert validate_session_id("valid-session_123")
    assert not validate_session_id("invalid!")
    assert not validate_session_id("x" * 200)  # Too long
    print("  ✓ Session ID validation works")
    
    print("\n✅ Helper functions test passed!")


if __name__ == "__main__":
    test_helpers()