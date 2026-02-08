"""
KEMTLS Client Wrapper

Wrapper for KEMTLS client functionality.
"""

from typing import Optional, Dict, Any
from kemtls.session import KEMTLSSession
from kemtls.channel import KEMTLSChannel


class KEMTLSClient:
    """
    KEMTLS Client
    
    Provides a simple interface for KEMTLS client operations.
    """
    
    def __init__(self):
        """Initialize KEMTLS client."""
        self.session = KEMTLSSession(is_server=False)
        self.channel: Optional[KEMTLSChannel] = None
    
    def perform_handshake(
        self,
        server_hello: Dict[str, Any],
        server_longterm_pk: bytes
    ) -> Dict[str, Any]:
        """
        Perform client-side handshake.
        
        Args:
            server_hello: ServerHello message from server
            server_longterm_pk: Trusted server long-term public key
        
        Returns:
            dict: ClientKeyExchange message to send to server
        """
        client_key_exchange, client_eph_pk = self.session.handshake.client_process_server_hello(
            server_hello,
            server_longterm_pk
        )
        
        return client_key_exchange
    
    def establish_secure_channel(self) -> KEMTLSChannel:
        """
        Establish encrypted channel after handshake.
        
        Returns:
            KEMTLSChannel: Encrypted communication channel
        """
        self.channel = self.session.establish_channel()
        return self.channel
    
    def send_encrypted(self, data: bytes) -> bytes:
        """
        Send encrypted data over the channel.
        
        Args:
            data: Plaintext data to send
        
        Returns:
            bytes: Encrypted message
        """
        if not self.channel:
            raise RuntimeError("Channel not established")
        
        return self.channel.send(data)
    
    def receive_encrypted(self, encrypted: bytes) -> bytes:
        """
        Receive and decrypt data from the channel.
        
        Args:
            encrypted: Encrypted message
        
        Returns:
            bytes: Decrypted plaintext
        """
        if not self.channel:
            raise RuntimeError("Channel not established")
        
        return self.channel.receive(encrypted)
    
    def get_client_ephemeral_pubkey(self) -> Optional[bytes]:
        """Get client's ephemeral public key."""
        return self.session.handshake.client_ephemeral_pk
    
    def get_client_ephemeral_secretkey(self) -> Optional[bytes]:
        """Get client's ephemeral secret key."""
        return self.session.handshake.client_ephemeral_sk
    
    def get_session_id(self) -> Optional[str]:
        """Get session ID."""
        return self.session.get_session_id()
