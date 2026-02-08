"""
KEMTLS Handshake Protocol

Implements the KEMTLS handshake where server authentication is performed via
KEM decapsulation rather than digital signatures.

Protocol Flow:
1. Server → Client: ServerHello (ephemeral_pk, longterm_pk, session_id)
2. Client → Server: ClientKeyExchange (ct_ephemeral, ct_longterm, client_eph_pk)
3. Both derive session keys from shared secrets

Key Innovation: Server proves identity by successfully decapsulating ciphertext,
not by providing a signature.
"""

import hashlib
from typing import Tuple, Dict, Any, Optional
from crypto.kyber_kem import KyberKEM
from crypto.dilithium_sig import DilithiumSignature
from crypto.kdf import KeyDerivation
from utils.encoding import base64url_encode, base64url_decode
from utils.serialization import serialize_message
from utils.helpers import generate_random_string



class KEMTLSHandshake:
    """
    KEMTLS Handshake Implementation
    
    Manages the KEM-based handshake protocol for establishing a secure session.
    """
    
    def __init__(self, is_server: bool = False):
        """
        Initialize KEMTLS handshake.
        
        Args:
            is_server (bool): True if this is the server side
        """
        self.is_server = is_server
        self.kem = KyberKEM()
        self.sig = DilithiumSignature()
        self.transcript = b""
        self.session_keys = None
        self.session_id = None
        
        # Server-side state
        self.server_ephemeral_sk = None
        self.server_longterm_sk = None
        
        # Client-side state
        self.client_ephemeral_sk = None
        self.client_ephemeral_pk = None
    
    def server_init_handshake(
        self,
        server_longterm_sk: bytes,
        server_longterm_pk: bytes
    ) -> Dict[str, Any]:
        """
        Server initiates the handshake by sending ServerHello.
        
        Args:
            server_longterm_sk: Server's long-term Kyber secret key
            server_longterm_pk: Server's long-term Kyber public key
        
        Returns:
            ServerHello message dictionary
        """
        # Generate ephemeral keypair
        eph_pk, eph_sk = self.kem.generate_keypair()
        self.server_ephemeral_sk = eph_sk
        self.server_longterm_sk = server_longterm_sk
        
        # Generate session ID
        self.session_id = generate_random_string(16)
        
        # Create ServerHello message
        server_hello = {
            'type': 'ServerHello',
            'server_ephemeral_pk': base64url_encode(eph_pk),
            'server_longterm_pk': base64url_encode(server_longterm_pk),
            'session_id': self.session_id
        }
        
        # Update transcript
        self.transcript += serialize_message(server_hello)
        
        return server_hello
    
    def server_process_client_key_exchange(
        self,
        client_key_exchange: Dict[str, Any]
    ) -> Dict[str, bytes]:
        """
        Server processes ClientKeyExchange and derives session keys.
        
        This is where server authentication happens - by successfully
        decapsulating the ciphertext!
        
        Args:
            client_key_exchange: ClientKeyExchange message
        
        Returns:
            Dictionary of session keys
        """
        # Update transcript
        self.transcript += serialize_message(client_key_exchange)
        
        # Extract ciphertexts
        ct_eph = base64url_decode(client_key_exchange['ciphertext_ephemeral'])
        ct_lt = base64url_decode(client_key_exchange['ciphertext_longterm'])
        
        # Decapsulate (this authenticates the server!)
        ss_eph = self.kem.decapsulate(self.server_ephemeral_sk, ct_eph)
        ss_lt = self.kem.decapsulate(self.server_longterm_sk, ct_lt)
        
        # Store client's ephemeral public key (for PoP binding)
        self.client_ephemeral_pk = base64url_decode(
            client_key_exchange['client_ephemeral_pk']
        )
        
        # Derive session keys
        transcript_hash = hashlib.sha256(self.transcript).digest()
        self.session_keys = KeyDerivation.derive_session_keys(
            [ss_eph, ss_lt],
            transcript_hash
        )
        
        return self.session_keys
    
    def client_process_server_hello(
        self,
        server_hello: Dict[str, Any],
        trusted_longterm_pk: bytes
    ) -> Tuple[Dict[str, Any], bytes]:
        """
        Client processes ServerHello and sends ClientKeyExchange.
        
        Args:
            server_hello: ServerHello message from server
            trusted_longterm_pk: Trusted server long-term public key
        
        Returns:
            (ClientKeyExchange message, client ephemeral public key)
        """
        # Update transcript
        self.transcript += serialize_message(server_hello)
        
        # Extract server keys
        server_eph_pk = base64url_decode(server_hello['server_ephemeral_pk'])
        server_lt_pk = base64url_decode(server_hello['server_longterm_pk'])
        
        # Verify server's long-term public key
        if server_lt_pk != trusted_longterm_pk:
            raise ValueError("Server authentication failed: untrusted long-term key")
        
        # Store session ID
        self.session_id = server_hello['session_id']
        
        # Encapsulate to both keys
        ct_eph, ss_eph = self.kem.encapsulate(server_eph_pk)
        ct_lt, ss_lt = self.kem.encapsulate(server_lt_pk)
        
        # Generate client ephemeral keypair for PoP
        client_eph_pk, client_eph_sk = self.sig.generate_keypair()
        self.client_ephemeral_pk = client_eph_pk
        self.client_ephemeral_sk = client_eph_sk
        
        # Create ClientKeyExchange
        client_key_exchange = {
            'type': 'ClientKeyExchange',
            'ciphertext_ephemeral': base64url_encode(ct_eph),
            'ciphertext_longterm': base64url_encode(ct_lt),
            'client_ephemeral_pk': base64url_encode(client_eph_pk),
            'session_id': self.session_id
        }
        
        # Update transcript
        self.transcript += serialize_message(client_key_exchange)
        
        # Derive session keys
        transcript_hash = hashlib.sha256(self.transcript).digest()
        self.session_keys = KeyDerivation.derive_session_keys(
            [ss_eph, ss_lt],
            transcript_hash
        )
        
        return client_key_exchange, client_eph_pk
    
    def get_session_keys(self) -> Optional[Dict[str, bytes]]:
        """Get the derived session keys."""
        return self.session_keys
    
    def get_session_id(self) -> Optional[str]:
        """Get the session ID."""
        return self.session_id
    
    def get_client_ephemeral_pubkey(self) -> Optional[bytes]:
        """Get client's ephemeral public key (server-side)."""
        return self.client_ephemeral_pk
