"""
ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD)

This module provides authenticated encryption for the KEMTLS secure channel.
ChaCha20-Poly1305 is a modern AEAD cipher that provides both confidentiality
and integrity/authenticity.

ChaCha20: Stream cipher for encryption
Poly1305: MAC for authentication

Key Size: 32 bytes (256 bits)
Nonce Size: 12 bytes (96 bits)
Tag Size: 16 bytes (128 bits)

Usage:
    >>> from crypto.aead import AEADCipher
    >>> import os
    >>> 
    >>> # Initialize with a key
    >>> key = os.urandom(32)
    >>> cipher = AEADCipher(key)
    >>> 
    >>> # Encrypt
    >>> plaintext = b"Secret message"
    >>> aad = b"Additional authenticated data"
    >>> ciphertext = cipher.encrypt(plaintext, aad)
    >>> 
    >>> # Decrypt
    >>> recovered = cipher.decrypt(ciphertext, aad)
    >>> assert recovered == plaintext
"""

import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag


class AEADCipher:
    """
    ChaCha20-Poly1305 Authenticated Encryption
    
    Provides authenticated encryption with associated data (AEAD) for
    the KEMTLS secure channel. This ensures both confidentiality and
    integrity of messages.
    
    Attributes:
        cipher: ChaCha20Poly1305 cipher instance
    """
    
    KEY_SIZE = 32  # 256 bits
    NONCE_SIZE = 12  # 96 bits
    TAG_SIZE = 16  # 128 bits
    
    def __init__(self, key: bytes):
        """
        Initialize the AEAD cipher with a key.
        
        Args:
            key (bytes): Encryption key (32 bytes)
        
        Raises:
            ValueError: If key is not 32 bytes
        
        Example:
            >>> import os
            >>> key = os.urandom(32)
            >>> cipher = AEADCipher(key)
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(
                f"Invalid key size: expected {self.KEY_SIZE} bytes, "
                f"got {len(key)} bytes"
            )
        
        self.cipher = ChaCha20Poly1305(key)
    
    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Encrypt plaintext with optional associated data.
        
        This operation:
        1. Generates a random nonce
        2. Encrypts plaintext using ChaCha20
        3. Computes authentication tag using Poly1305
        4. Returns: nonce || ciphertext || tag
        
        Args:
            plaintext (bytes): Data to encrypt (arbitrary length)
            associated_data (bytes, optional): Additional data to authenticate
                                               but not encrypt
        
        Returns:
            bytes: Encrypted message = nonce (12B) || ciphertext || tag (16B)
        
        Example:
            >>> cipher = AEADCipher(os.urandom(32))
            >>> plaintext = b"Secret message"
            >>> encrypted = cipher.encrypt(plaintext)
            >>> len(encrypted) == 12 + len(plaintext) + 16
            True
        """
        if not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be bytes")
        
        if associated_data is not None and not isinstance(associated_data, bytes):
            raise TypeError("Associated data must be bytes")
        
        # Generate random nonce
        nonce = os.urandom(self.NONCE_SIZE)
        
        # Encrypt and authenticate
        # ChaCha20Poly1305.encrypt returns: ciphertext || tag
        ciphertext_with_tag = self.cipher.encrypt(
            nonce,
            plaintext,
            associated_data
        )
        
        # Return: nonce || ciphertext || tag
        return nonce + ciphertext_with_tag
    
    def decrypt(self, encrypted: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt ciphertext and verify authentication tag.
        
        This operation:
        1. Extracts nonce from encrypted message
        2. Verifies authentication tag
        3. Decrypts ciphertext using ChaCha20
        4. Returns plaintext
        
        Args:
            encrypted (bytes): Encrypted message (nonce || ciphertext || tag)
            associated_data (bytes, optional): Additional authenticated data
                                               used during encryption
        
        Returns:
            bytes: Decrypted plaintext
        
        Raises:
            ValueError: If encrypted message is too short
            InvalidTag: If authentication tag verification fails
        
        Example:
            >>> cipher = AEADCipher(os.urandom(32))
            >>> plaintext = b"Secret message"
            >>> encrypted = cipher.encrypt(plaintext)
            >>> decrypted = cipher.decrypt(encrypted)
            >>> decrypted == plaintext
            True
        """
        if not isinstance(encrypted, bytes):
            raise TypeError("Encrypted data must be bytes")
        
        if associated_data is not None and not isinstance(associated_data, bytes):
            raise TypeError("Associated data must be bytes")
        
        # Minimum size: nonce (12) + tag (16) = 28 bytes
        if len(encrypted) < self.NONCE_SIZE + self.TAG_SIZE:
            raise ValueError(
                f"Encrypted message too short: minimum {self.NONCE_SIZE + self.TAG_SIZE} bytes, "
                f"got {len(encrypted)} bytes"
            )
        
        # Extract nonce and ciphertext+tag
        nonce = encrypted[:self.NONCE_SIZE]
        ciphertext_with_tag = encrypted[self.NONCE_SIZE:]
        
        try:
            # Decrypt and verify
            plaintext = self.cipher.decrypt(
                nonce,
                ciphertext_with_tag,
                associated_data
            )
            
            return plaintext
        except InvalidTag:
            raise ValueError("Authentication tag verification failed - data may be corrupted or tampered")
    
    @classmethod
    def generate_key(cls) -> bytes:
        """
        Generate a random encryption key.
        
        Returns:
            bytes: Random 32-byte key suitable for ChaCha20-Poly1305
        
        Example:
            >>> key = AEADCipher.generate_key()
            >>> len(key) == 32
            True
        """
        return os.urandom(cls.KEY_SIZE)
    
    def get_cipher_info(self) -> dict:
        """
        Get information about the cipher.
        
        Returns:
            dict: Cipher parameters and sizes
        """
        return {
            "algorithm": "ChaCha20-Poly1305",
            "type": "AEAD (Authenticated Encryption with Associated Data)",
            "key_size": self.KEY_SIZE,
            "nonce_size": self.NONCE_SIZE,
            "tag_size": self.TAG_SIZE,
            "encryption": "ChaCha20 stream cipher",
            "authentication": "Poly1305 MAC"
        }


def test_aead_cipher():
    """
    Test the AEAD cipher implementation.
    
    Verifies:
    1. Encryption and decryption
    2. Associated data authentication
    3. Tag verification
    4. Tampering detection
    """
    print("Testing ChaCha20-Poly1305 AEAD...")
    
    # Generate key
    print("  Generating key...")
    key = AEADCipher.generate_key()
    assert len(key) == AEADCipher.KEY_SIZE
    print(f"  ✓ Key: {len(key)} bytes")
    
    # Initialize cipher
    cipher = AEADCipher(key)
    
    # Test encryption without AAD
    print("  Testing encryption without AAD...")
    plaintext = b"This is a secret message!"
    encrypted = cipher.encrypt(plaintext)
    assert len(encrypted) == AEADCipher.NONCE_SIZE + len(plaintext) + AEADCipher.TAG_SIZE
    print(f"  ✓ Encrypted: {len(encrypted)} bytes")
    
    # Test decryption
    print("  Testing decryption...")
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == plaintext
    print("  ✓ Decryption successful")
    
    # Test encryption with AAD
    print("  Testing encryption with AAD...")
    aad = b"sequence_number_12345"
    encrypted_with_aad = cipher.encrypt(plaintext, aad)
    decrypted_with_aad = cipher.decrypt(encrypted_with_aad, aad)
    assert decrypted_with_aad == plaintext
    print("  ✓ AAD encryption/decryption successful")
    
    # Test tampering detection
    print("  Testing tampering detection...")
    # Modify ciphertext
    tampered = bytearray(encrypted)
    tampered[-1] ^= 0xFF  # Flip bits in tag
    
    try:
        cipher.decrypt(bytes(tampered))
        assert False, "Should have detected tampering!"
    except ValueError as e:
        assert "Authentication tag verification failed" in str(e)
        print("  ✓ Tampering detected")
    
    # Test wrong AAD detection
    print("  Testing wrong AAD detection...")
    try:
        cipher.decrypt(encrypted_with_aad, b"wrong_aad")
        assert False, "Should have detected wrong AAD!"
    except ValueError as e:
        assert "Authentication tag verification failed" in str(e)
        print("  ✓ Wrong AAD detected")
    
    # Display cipher info
    info = cipher.get_cipher_info()
    print("\n  Cipher Information:")
    for key, value in info.items():
        print(f"    {key}: {value}")
    
    print("\n✅ ChaCha20-Poly1305 AEAD test passed!")


if __name__ == "__main__":
    test_aead_cipher()
