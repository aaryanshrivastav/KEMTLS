"""
HKDF (HMAC-based Key Derivation Function)

This module provides key derivation functionality for KEMTLS session keys.
HKDF is used to derive multiple session keys from the shared secrets
established during the KEMTLS handshake.

Based on RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function

Usage:
    >>> from crypto.kdf import KeyDerivation
    >>> 
    >>> # Shared secrets from KEMTLS
    >>> ss_ephemeral = os.urandom(32)
    >>> ss_longterm = os.urandom(32)
    >>> transcript = b"handshake_messages_hash"
    >>> 
    >>> # Derive session keys
    >>> keys = KeyDerivation.derive_session_keys(
    ...     [ss_ephemeral, ss_longterm],
    ...     transcript
    ... )
    >>> 
    >>> # Access individual keys
    >>> client_write_key = keys['client_write_key']
    >>> server_write_key = keys['server_write_key']
"""

import hashlib
from typing import List, Dict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class KeyDerivation:
    """
    Key Derivation for KEMTLS Sessions
    
    Derives multiple session keys from KEMTLS shared secrets using HKDF-SHA256.
    This ensures that different keys are used for different purposes, following
    the principle of key separation.
    
    Derived Keys:
        - client_write_key: For client → server encryption
        - server_write_key: For server → client encryption
        - session_key: General session identifier
        - pop_key: For proof-of-possession binding (optional)
    """
    
    HASH_ALGORITHM = hashes.SHA256()
    KEY_LENGTH = 32  # 256 bits
    
    @classmethod
    def derive_session_keys(
        cls,
        shared_secrets: List[bytes],
        transcript: bytes,
        include_pop_key: bool = True
    ) -> Dict[str, bytes]:
        """
        Derive session keys from KEMTLS shared secrets.
        
        This function implements the key derivation process:
        1. Combine all inputs (shared secrets + transcript)
        2. Extract: Generate master secret using HKDF-Extract
        3. Expand: Derive individual keys using HKDF-Expand
        
        Args:
            shared_secrets (List[bytes]): List of shared secrets from KEM operations
                                          Typically: [ephemeral_ss, longterm_ss]
            transcript (bytes): Hash of handshake messages for binding
            include_pop_key (bool): Whether to derive PoP key (default: True)
        
        Returns:
            Dict[str, bytes]: Dictionary containing derived keys:
                - 'client_write_key': 32 bytes
                - 'server_write_key': 32 bytes
                - 'session_key': 32 bytes
                - 'pop_key': 32 bytes (if include_pop_key=True)
        
        Example:
            >>> import os
            >>> ss1 = os.urandom(32)
            >>> ss2 = os.urandom(32)
            >>> transcript = hashlib.sha256(b"handshake").digest()
            >>> keys = KeyDerivation.derive_session_keys([ss1, ss2], transcript)
            >>> len(keys['client_write_key']) == 32
            True
        """
        # Validate inputs
        for i, ss in enumerate(shared_secrets):
            if not isinstance(ss, bytes):
                raise TypeError(f"Shared secret {i} must be bytes")
            if len(ss) != 32:
                raise ValueError(f"Shared secret {i} must be 32 bytes, got {len(ss)}")
        
        if not isinstance(transcript, bytes):
            raise TypeError("Transcript must be bytes")
        
        # Combine all input key material
        # Format: ss1 || ss2 || ... || transcript
        input_key_material = b"".join(shared_secrets) + transcript
        
        # Step 1: Extract - derive master secret
        master_secret = cls._hkdf_extract(input_key_material)
        
        # Step 2: Expand - derive individual keys
        keys = {
            'client_write_key': cls._hkdf_expand(
                master_secret,
                b"KEMTLS client write key",
                cls.KEY_LENGTH
            ),
            'server_write_key': cls._hkdf_expand(
                master_secret,
                b"KEMTLS server write key",
                cls.KEY_LENGTH
            ),
            'session_key': cls._hkdf_expand(
                master_secret,
                b"KEMTLS session key",
                cls.KEY_LENGTH
            ),
        }
        
        # Optionally derive PoP key
        if include_pop_key:
            keys['pop_key'] = cls._hkdf_expand(
                master_secret,
                b"KEMTLS proof-of-possession key",
                cls.KEY_LENGTH
            )
        
        return keys
    
    @classmethod
    def _hkdf_extract(cls, input_key_material: bytes, salt: bytes = None) -> bytes:
        """
        HKDF-Extract: Derive a master secret from input key material.
        
        Args:
            input_key_material (bytes): Combined shared secrets and transcript
            salt (bytes, optional): Salt value (default: zeros)
        
        Returns:
            bytes: Master secret (32 bytes)
        """
        if salt is None:
            salt = b"\x00" * cls.KEY_LENGTH
        
        # HKDF-Extract = HMAC-Hash(salt, IKM)
        hmac = hashlib.pbkdf2_hmac(
            'sha256',
            input_key_material,
            salt,
            1,  # iterations
            cls.KEY_LENGTH
        )
        
        return hmac
    
    @classmethod
    def _hkdf_expand(cls, master_secret: bytes, info: bytes, length: int) -> bytes:
        """
        HKDF-Expand: Derive a key from the master secret.
        
        Args:
            master_secret (bytes): The master secret from HKDF-Extract
            info (bytes): Context-specific information
            length (int): Desired key length
        
        Returns:
            bytes: Derived key
        """
        hkdf = HKDF(
            algorithm=cls.HASH_ALGORITHM,
            length=length,
            salt=None,
            info=info
        )
        
        return hkdf.derive(master_secret)
    
    @classmethod
    def derive_single_key(
        cls,
        shared_secret: bytes,
        context: bytes,
        length: int = KEY_LENGTH
    ) -> bytes:
        """
        Derive a single key from a shared secret (simplified interface).
        
        Args:
            shared_secret (bytes): A single shared secret (32 bytes)
            context (bytes): Context information for key derivation
            length (int): Desired key length (default: 32 bytes)
        
        Returns:
            bytes: Derived key
        
        Example:
            >>> import os
            >>> ss = os.urandom(32)
            >>> key = KeyDerivation.derive_single_key(ss, b"encryption key")
            >>> len(key) == 32
            True
        """
        if not isinstance(shared_secret, bytes):
            raise TypeError("Shared secret must be bytes")
        
        if len(shared_secret) != 32:
            raise ValueError(f"Shared secret must be 32 bytes, got {len(shared_secret)}")
        
        master_secret = cls._hkdf_extract(shared_secret)
        return cls._hkdf_expand(master_secret, context, length)


def test_key_derivation():
    """
    Test the key derivation implementation.
    
    Verifies:
    1. Session key derivation
    2. Key uniqueness
    3. Deterministic derivation
    4. Single key derivation
    """
    import os
    
    print("Testing HKDF Key Derivation...")
    
    # Generate test inputs
    print("  Generating test inputs...")
    ss_ephemeral = os.urandom(32)
    ss_longterm = os.urandom(32)
    transcript = hashlib.sha256(b"test_handshake_transcript").digest()
    
    # Test session key derivation
    print("  Deriving session keys...")
    keys = KeyDerivation.derive_session_keys(
        [ss_ephemeral, ss_longterm],
        transcript
    )
    
    # Verify all keys are present
    expected_keys = ['client_write_key', 'server_write_key', 'session_key', 'pop_key']
    for key_name in expected_keys:
        assert key_name in keys, f"Missing key: {key_name}"
        assert len(keys[key_name]) == 32, f"Wrong key size: {key_name}"
    print(f"  ✓ Derived {len(keys)} keys, each 32 bytes")
    
    # Verify keys are unique
    print("  Verifying key uniqueness...")
    key_values = list(keys.values())
    assert len(key_values) == len(set(key_values)), "Keys are not unique!"
    print("  ✓ All keys are unique")
    
    # Test deterministic derivation
    print("  Testing deterministic derivation...")
    keys2 = KeyDerivation.derive_session_keys(
        [ss_ephemeral, ss_longterm],
        transcript
    )
    for key_name in expected_keys:
        assert keys[key_name] == keys2[key_name], f"Non-deterministic: {key_name}"
    print("  ✓ Derivation is deterministic")
    
    # Test different inputs produce different keys
    print("  Testing different inputs...")
    different_ss = os.urandom(32)
    keys3 = KeyDerivation.derive_session_keys(
        [different_ss, ss_longterm],
        transcript
    )
    assert keys['client_write_key'] != keys3['client_write_key']
    print("  ✓ Different inputs produce different keys")
    
    # Test single key derivation
    print("  Testing single key derivation...")
    single_key = KeyDerivation.derive_single_key(
        ss_ephemeral,
        b"test context"
    )
    assert len(single_key) == 32
    print("  ✓ Single key derivation works")
    
    # Display key information
    print("\n  Derived Keys:")
    for key_name, key_value in keys.items():
        print(f"    {key_name}: {key_value.hex()[:32]}...")
    
    print("\n✅ HKDF key derivation test passed!")


if __name__ == "__main__":
    test_key_derivation()
