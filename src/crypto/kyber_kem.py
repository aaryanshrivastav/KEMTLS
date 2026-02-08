"""
Kyber768 Key Encapsulation Mechanism (KEM)

This module provides a wrapper around the Kyber768 post-quantum KEM algorithm
from liboqs. Kyber is a NIST-standardized post-quantum key encapsulation mechanism
based on the Module Learning With Errors (MLWE) problem.

Security Level: NIST Level 3 (equivalent to AES-192)
Public Key Size: 1184 bytes
Secret Key Size: 2400 bytes
Ciphertext Size: 1088 bytes
Shared Secret Size: 32 bytes

Usage:
    >>> from crypto.kyber_kem import KyberKEM
    >>> kem = KyberKEM()
    >>> 
    >>> # Key generation
    >>> public_key, secret_key = kem.generate_keypair()
    >>> 
    >>> # Encapsulation (sender)
    >>> ciphertext, shared_secret = kem.encapsulate(public_key)
    >>> 
    >>> # Decapsulation (receiver)
    >>> shared_secret_recovered = kem.decapsulate(secret_key, ciphertext)
    >>> 
    >>> assert shared_secret == shared_secret_recovered
"""

import oqs
from typing import Tuple


class KyberKEM:
    """
    Kyber768 Key Encapsulation Mechanism
    
    Provides post-quantum secure key encapsulation using the Kyber768 algorithm.
    Used in KEMTLS for both ephemeral and long-term key exchange.
    
    Attributes:
        algorithm (str): The Kyber variant being used (Kyber768)
    """
    
    ALGORITHM = "Kyber768"
    PUBLIC_KEY_SIZE = 1184
    SECRET_KEY_SIZE = 2400
    CIPHERTEXT_SIZE = 1088
    SHARED_SECRET_SIZE = 32
    
    def __init__(self):
        """Initialize the Kyber KEM with Kyber768 parameters."""
        self.algorithm = self.ALGORITHM
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new Kyber768 keypair.
        
        Returns:
            Tuple[bytes, bytes]: (public_key, secret_key)
                - public_key: 1184 bytes, can be shared publicly
                - secret_key: 2400 bytes, must be kept secret
        
        Example:
            >>> kem = KyberKEM()
            >>> pk, sk = kem.generate_keypair()
            >>> len(pk) == 1184
            True
            >>> len(sk) == 2400
            True
        """
        try:
            kem_instance = oqs.KeyEncapsulation(self.algorithm)
            public_key = kem_instance.generate_keypair()
            secret_key = kem_instance.export_secret_key()
            
            return public_key, secret_key
        except Exception as e:
            raise RuntimeError(f"Kyber keypair generation failed: {e}")
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using the recipient's public key.
        
        This operation:
        1. Generates a random message
        2. Encapsulates it using the public key
        3. Derives a shared secret from the message
        
        Args:
            public_key (bytes): The recipient's Kyber public key (1184 bytes)
        
        Returns:
            Tuple[bytes, bytes]: (ciphertext, shared_secret)
                - ciphertext: 1088 bytes, to be sent to recipient
                - shared_secret: 32 bytes, the encapsulated secret
        
        Raises:
            ValueError: If public_key is invalid or wrong size
            RuntimeError: If encapsulation fails
        
        Example:
            >>> kem = KyberKEM()
            >>> pk, sk = kem.generate_keypair()
            >>> ct, ss = kem.encapsulate(pk)
            >>> len(ct) == 1088
            True
            >>> len(ss) == 32
            True
        """
        if len(public_key) != self.PUBLIC_KEY_SIZE:
            raise ValueError(
                f"Invalid public key size: expected {self.PUBLIC_KEY_SIZE}, "
                f"got {len(public_key)}"
            )
        
        try:
            kem_instance = oqs.KeyEncapsulation(self.algorithm)
            ciphertext, shared_secret = kem_instance.encap_secret(public_key)
            
            return ciphertext, shared_secret
        except Exception as e:
            raise RuntimeError(f"Kyber encapsulation failed: {e}")
    
    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate a ciphertext to recover the shared secret.
        
        This operation:
        1. Decrypts the ciphertext using the secret key
        2. Recovers the original message
        3. Derives the same shared secret
        
        Args:
            secret_key (bytes): The recipient's Kyber secret key (2400 bytes)
            ciphertext (bytes): The encapsulated ciphertext (1088 bytes)
        
        Returns:
            bytes: The shared secret (32 bytes)
        
        Raises:
            ValueError: If secret_key or ciphertext are invalid
            RuntimeError: If decapsulation fails
        
        Example:
            >>> kem = KyberKEM()
            >>> pk, sk = kem.generate_keypair()
            >>> ct, ss1 = kem.encapsulate(pk)
            >>> ss2 = kem.decapsulate(sk, ct)
            >>> ss1 == ss2
            True
        """
        if len(secret_key) != self.SECRET_KEY_SIZE:
            raise ValueError(
                f"Invalid secret key size: expected {self.SECRET_KEY_SIZE}, "
                f"got {len(secret_key)}"
            )
        
        if len(ciphertext) != self.CIPHERTEXT_SIZE:
            raise ValueError(
                f"Invalid ciphertext size: expected {self.CIPHERTEXT_SIZE}, "
                f"got {len(ciphertext)}"
            )
        
        try:
            kem_instance = oqs.KeyEncapsulation(self.algorithm, secret_key)
            shared_secret = kem_instance.decap_secret(ciphertext)
            
            return shared_secret
        except Exception as e:
            raise RuntimeError(f"Kyber decapsulation failed: {e}")
    
    def get_algorithm_info(self) -> dict:
        """
        Get information about the Kyber768 algorithm.
        
        Returns:
            dict: Algorithm parameters and sizes
        """
        return {
            "algorithm": self.algorithm,
            "security_level": "NIST Level 3",
            "public_key_size": self.PUBLIC_KEY_SIZE,
            "secret_key_size": self.SECRET_KEY_SIZE,
            "ciphertext_size": self.CIPHERTEXT_SIZE,
            "shared_secret_size": self.SHARED_SECRET_SIZE,
            "type": "Key Encapsulation Mechanism",
            "hardness_assumption": "Module-LWE"
        }


def test_kyber_kem():
    """
    Test the Kyber KEM implementation.
    
    Verifies:
    1. Keypair generation
    2. Encapsulation
    3. Decapsulation
    4. Shared secret agreement
    """
    print("Testing Kyber768 KEM...")
    
    kem = KyberKEM()
    
    # Test keypair generation
    print("  Generating keypair...")
    pk, sk = kem.generate_keypair()
    assert len(pk) == KyberKEM.PUBLIC_KEY_SIZE
    assert len(sk) == KyberKEM.SECRET_KEY_SIZE
    print(f"  ✓ Public key: {len(pk)} bytes")
    print(f"  ✓ Secret key: {len(sk)} bytes")
    
    # Test encapsulation
    print("  Encapsulating...")
    ct, ss1 = kem.encapsulate(pk)
    assert len(ct) == KyberKEM.CIPHERTEXT_SIZE
    assert len(ss1) == KyberKEM.SHARED_SECRET_SIZE
    print(f"  ✓ Ciphertext: {len(ct)} bytes")
    print(f"  ✓ Shared secret: {len(ss1)} bytes")
    
    # Test decapsulation
    print("  Decapsulating...")
    ss2 = kem.decapsulate(sk, ct)
    assert len(ss2) == KyberKEM.SHARED_SECRET_SIZE
    print(f"  ✓ Recovered shared secret: {len(ss2)} bytes")
    
    # Verify shared secrets match
    assert ss1 == ss2, "Shared secrets do not match!"
    print("  ✓ Shared secrets match")
    
    # Display algorithm info
    info = kem.get_algorithm_info()
    print("\n  Algorithm Information:")
    for key, value in info.items():
        print(f"    {key}: {value}")
    
    print("\n✅ Kyber768 KEM test passed!")


if __name__ == "__main__":
    test_kyber_kem()
