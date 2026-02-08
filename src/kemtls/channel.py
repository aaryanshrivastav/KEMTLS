"""
KEMTLS Encrypted Channel

Provides encrypted communication over a KEMTLS session using the derived session keys.
Uses ChaCha20-Poly1305 AEAD for encryption and includes replay protection via sequence numbers.
"""

import struct
from typing import Optional
from crypto.aead import AEADCipher


class KEMTLSChannel:
    """
    KEMTLS Secure Communication Channel
    
    Provides bidirectional encrypted communication using session keys
    derived from the KEMTLS handshake.
    """
    
    def __init__(self, session_keys: dict, is_server: bool = False):
        """
        Initialize encrypted channel.
        
        Args:
            session_keys: Dictionary containing 'client_write_key' and 'server_write_key'
            is_server: True if this is the server side
        """
        self.is_server = is_server
        
        # Select appropriate keys based on role
        if is_server:
            self.write_key = session_keys['server_write_key']
            self.read_key = session_keys['client_write_key']
        else:
            self.write_key = session_keys['client_write_key']
            self.read_key = session_keys['server_write_key']
        
        # Initialize AEAD ciphers
        self.write_cipher = AEADCipher(self.write_key)
        self.read_cipher = AEADCipher(self.read_key)
        
        # Sequence numbers for replay protection
        self.write_seq = 0
        self.read_seq = 0
    
    def send(self, data: bytes) -> bytes:
        """
        Encrypt and send data over the channel.
        
        Args:
            data: Plaintext data to send
        
        Returns:
            bytes: Encrypted message (seq_num || nonce || ciphertext || tag)
        """
        # Create AAD with sequence number
        aad = struct.pack('>Q', self.write_seq)
        
        # Encrypt
        ciphertext = self.write_cipher.encrypt(data, aad)
        
        # Increment sequence
        self.write_seq += 1
        
        # Return: seq_num || ciphertext
        return aad + ciphertext
    
    def receive(self, encrypted: bytes) -> bytes:
        """
        Receive and decrypt data from the channel.
        
        Args:
            encrypted: Encrypted message
        
        Returns:
            bytes: Decrypted plaintext
        
        Raises:
            ValueError: If sequence number is wrong or decryption fails
        """
        # Extract sequence number
        seq_bytes = encrypted[:8]
        ciphertext = encrypted[8:]
        
        received_seq = struct.unpack('>Q', seq_bytes)[0]
        
        # Check sequence (replay protection)
        if received_seq != self.read_seq:
            raise ValueError(
                f"Sequence mismatch: expected {self.read_seq}, got {received_seq}"
            )
        
        # Decrypt
        plaintext = self.read_cipher.decrypt(ciphertext, seq_bytes)
        
        # Increment sequence
        self.read_seq += 1
        
        return plaintext