"""
Dilithium3 Digital Signature Scheme

This module provides a wrapper around the Dilithium3 post-quantum digital signature
algorithm from liboqs. Dilithium is a NIST-standardized signature scheme based on
the Module Learning With Errors (MLWE) problem and Fiat-Shamir with aborts.

Security Level: NIST Level 3 (equivalent to AES-192)
Public Key Size: 1952 bytes
Secret Key Size: 4000 bytes
Signature Size: 3293 bytes

Usage:
    >>> from crypto.dilithium_sig import DilithiumSignature
    >>> sig_scheme = DilithiumSignature()
    >>> 
    >>> # Key generation
    >>> public_key, secret_key = sig_scheme.generate_keypair()
    >>> 
    >>> # Signing
    >>> message = b"Hello, post-quantum world!"
    >>> signature = sig_scheme.sign(secret_key, message)
    >>> 
    >>> # Verification
    >>> is_valid = sig_scheme.verify(public_key, message, signature)
    >>> assert is_valid
"""

import oqs
from typing import Tuple


class DilithiumSignature:
    """
    Dilithium3 Digital Signature Scheme
    
    Provides post-quantum secure digital signatures using the Dilithium3 algorithm.
    Used in KEMTLS-OIDC for:
    1. Signing ID tokens (Authorization Server)
    2. Proof-of-Possession (Client)
    
    Attributes:
        algorithm (str): The Dilithium variant being used (Dilithium3)
    """
    
    ALGORITHM = "Dilithium3"
    PUBLIC_KEY_SIZE = 1952
    SECRET_KEY_SIZE = 4000
    SIGNATURE_SIZE = 3293
    
    def __init__(self):
        """Initialize the Dilithium signature scheme with Dilithium3 parameters."""
        self.algorithm = self.ALGORITHM
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new Dilithium3 keypair.
        
        Returns:
            Tuple[bytes, bytes]: (public_key, secret_key)
                - public_key: 1952 bytes, can be shared publicly
                - secret_key: 4000 bytes, must be kept secret
        
        Example:
            >>> sig = DilithiumSignature()
            >>> pk, sk = sig.generate_keypair()
            >>> len(pk) == 1952
            True
            >>> len(sk) == 4000
            True
        """
        try:
            sig_instance = oqs.Signature(self.algorithm)
            public_key = sig_instance.generate_keypair()
            secret_key = sig_instance.export_secret_key()
            
            return public_key, secret_key
        except Exception as e:
            raise RuntimeError(f"Dilithium keypair generation failed: {e}")
    
    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """
        Sign a message using Dilithium3.
        
        This operation creates a digital signature that proves:
        1. The message came from the holder of the secret key
        2. The message has not been tampered with
        
        Args:
            secret_key (bytes): The signer's Dilithium secret key (4000 bytes)
            message (bytes): The message to sign (arbitrary length)
        
        Returns:
            bytes: The signature (3293 bytes)
        
        Raises:
            ValueError: If secret_key is invalid
            RuntimeError: If signing fails
        
        Example:
            >>> sig = DilithiumSignature()
            >>> pk, sk = sig.generate_keypair()
            >>> message = b"Important message"
            >>> signature = sig.sign(sk, message)
            >>> len(signature) == 3293
            True
        """
        if len(secret_key) != self.SECRET_KEY_SIZE:
            raise ValueError(
                f"Invalid secret key size: expected {self.SECRET_KEY_SIZE}, "
                f"got {len(secret_key)}"
            )
        
        if not isinstance(message, bytes):
            raise TypeError("Message must be bytes")
        
        try:
            sig_instance = oqs.Signature(self.algorithm, secret_key)
            signature = sig_instance.sign(message)
            
            return signature
        except Exception as e:
            raise RuntimeError(f"Dilithium signing failed: {e}")
    
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify a Dilithium3 signature.
        
        This operation checks:
        1. The signature is valid for the given message
        2. The signature was created using the secret key corresponding to public_key
        
        Args:
            public_key (bytes): The signer's Dilithium public key (1952 bytes)
            message (bytes): The original message (arbitrary length)
            signature (bytes): The signature to verify (3293 bytes)
        
        Returns:
            bool: True if signature is valid, False otherwise
        
        Raises:
            ValueError: If public_key or signature are invalid sizes
        
        Example:
            >>> sig = DilithiumSignature()
            >>> pk, sk = sig.generate_keypair()
            >>> message = b"Important message"
            >>> signature = sig.sign(sk, message)
            >>> sig.verify(pk, message, signature)
            True
            >>> sig.verify(pk, b"Different message", signature)
            False
        """
        if len(public_key) != self.PUBLIC_KEY_SIZE:
            raise ValueError(
                f"Invalid public key size: expected {self.PUBLIC_KEY_SIZE}, "
                f"got {len(public_key)}"
            )
        
        if len(signature) != self.SIGNATURE_SIZE:
            raise ValueError(
                f"Invalid signature size: expected {self.SIGNATURE_SIZE}, "
                f"got {len(signature)}"
            )
        
        if not isinstance(message, bytes):
            raise TypeError("Message must be bytes")
        
        try:
            sig_instance = oqs.Signature(self.algorithm)
            is_valid = sig_instance.verify(message, signature, public_key)
            
            return is_valid
        except Exception as e:
            # Verification failure should return False, not raise exception
            return False
    
    def get_algorithm_info(self) -> dict:
        """
        Get information about the Dilithium3 algorithm.
        
        Returns:
            dict: Algorithm parameters and sizes
        """
        return {
            "algorithm": self.algorithm,
            "security_level": "NIST Level 3",
            "public_key_size": self.PUBLIC_KEY_SIZE,
            "secret_key_size": self.SECRET_KEY_SIZE,
            "signature_size": self.SIGNATURE_SIZE,
            "type": "Digital Signature",
            "hardness_assumption": "Module-LWE + Fiat-Shamir"
        }


def test_dilithium_signature():
    """
    Test the Dilithium signature implementation.
    
    Verifies:
    1. Keypair generation
    2. Signing
    3. Signature verification (valid)
    4. Signature verification (invalid message)
    5. Signature verification (invalid signature)
    """
    print("Testing Dilithium3 Signatures...")
    
    sig = DilithiumSignature()
    
    # Test keypair generation
    print("  Generating keypair...")
    pk, sk = sig.generate_keypair()
    assert len(pk) == DilithiumSignature.PUBLIC_KEY_SIZE
    assert len(sk) == DilithiumSignature.SECRET_KEY_SIZE
    print(f"  ✓ Public key: {len(pk)} bytes")
    print(f"  ✓ Secret key: {len(sk)} bytes")
    
    # Test signing
    print("  Signing message...")
    message = b"This is a test message for Dilithium3 signature"
    signature = sig.sign(sk, message)
    assert len(signature) == DilithiumSignature.SIGNATURE_SIZE
    print(f"  ✓ Signature: {len(signature)} bytes")
    
    # Test valid verification
    print("  Verifying valid signature...")
    is_valid = sig.verify(pk, message, signature)
    assert is_valid, "Valid signature should verify!"
    print("  ✓ Valid signature verified")
    
    # Test invalid message
    print("  Testing with tampered message...")
    tampered_message = b"This is a TAMPERED message"
    is_valid = sig.verify(pk, tampered_message, signature)
    assert not is_valid, "Tampered message should not verify!"
    print("  ✓ Tampered message rejected")
    
    # Test invalid signature
    print("  Testing with invalid signature...")
    invalid_sig = b"\x00" * DilithiumSignature.SIGNATURE_SIZE
    is_valid = sig.verify(pk, message, invalid_sig)
    assert not is_valid, "Invalid signature should not verify!"
    print("  ✓ Invalid signature rejected")
    
    # Display algorithm info
    info = sig.get_algorithm_info()
    print("\n  Algorithm Information:")
    for key, value in info.items():
        print(f"    {key}: {value}")
    
    print("\n✅ Dilithium3 signature test passed!")


if __name__ == "__main__":
    test_dilithium_signature()
