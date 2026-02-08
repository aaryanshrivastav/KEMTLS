"""
KEMTLS Session Management

Manages KEMTLS sessions including handshake execution and channel creation.
"""

from typing import Optional, Dict, Any
from .handshake import KEMTLSHandshake
from .channel import KEMTLSChannel


class KEMTLSSession:
    """
    Complete KEMTLS Session
    
    Manages the full lifecycle of a KEMTLS session from handshake to
    encrypted communication.
    """
    
    def __init__(self, is_server: bool = False):
        """
        Initialize session.
        
        Args:
            is_server: True if this is the server side
        """
        self.is_server = is_server
        self.handshake = KEMTLSHandshake(is_server)
        self.channel: Optional[KEMTLSChannel] = None
        self.is_established = False
    
    def establish_channel(self) -> KEMTLSChannel:
        """
        Establish the encrypted channel after handshake completes.
        
        Returns:
            KEMTLSChannel instance
        
        Raises:
            RuntimeError: If handshake not complete
        """
        session_keys = self.handshake.get_session_keys()
        if not session_keys:
            raise RuntimeError("Handshake not complete - cannot establish channel")
        
        self.channel = KEMTLSChannel(session_keys, self.is_server)
        self.is_established = True
        
        return self.channel
    
    def get_session_id(self) -> Optional[str]:
        """Get session ID."""
        return self.handshake.get_session_id()
    
    def get_client_ephemeral_pubkey(self) -> Optional[bytes]:
        """Get client's ephemeral public key (for PoP binding)."""
        return self.handshake.get_client_ephemeral_pubkey()