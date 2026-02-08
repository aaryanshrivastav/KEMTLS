"""
Post-Quantum JWT Handler

Creates and verifies JSON Web Tokens using Dilithium3 signatures.
Implements proof-of-possession binding by embedding client public keys in tokens.
"""

import json
import time
from typing import Dict, Any, Optional
from crypto.dilithium_sig import DilithiumSignature
from utils.encoding import base64url_encode, base64url_decode
from utils.helpers import create_jwk_from_dilithium_pubkey, extract_pubkey_from_jwk, get_timestamp


class PQJWT:
    """
    Post-Quantum JSON Web Token Handler
    
    Creates and verifies JWTs using Dilithium3 digital signatures.
    Supports proof-of-possession token binding.
    """
    
    def __init__(self):
        """Initialize JWT handler."""
        self.sig = DilithiumSignature()
    
    def create_id_token(
        self,
        claims: Dict[str, Any],
        issuer_sk: bytes,
        issuer_pk: bytes,
        client_ephemeral_pk: Optional[bytes] = None,
        session_key: Optional[bytes] = None,
        session_id: Optional[str] = None
    ) -> str:
        """
        Create an ID token (JWT) signed with Dilithium3.
        
        Args:
            claims: Token payload claims
            issuer_sk: Issuer's Dilithium secret key
            issuer_pk: Issuer's Dilithium public key
            client_ephemeral_pk: Client's ephemeral public key for PoP binding
            session_key: KEMTLS session key
            session_id: KEMTLS session ID
        
        Returns:
            str: Complete JWT (header.payload.signature)
        """
        # Create header
        header = {
            'alg': 'DILITHIUM3',
            'typ': 'JWT',
            'kid': 'server-signing-key'
        }
        
        # Add PoP confirmation claim if client key provided
        if client_ephemeral_pk:
            claims['cnf'] = {
                'jwk': create_jwk_from_dilithium_pubkey(
                    client_ephemeral_pk,
                    kid='client-ephemeral'
                )
            }
            if session_id:
                claims['cnf']['session_id'] = session_id
            if 'exp' in claims:
                # Session binding expires earlier than token
                claims['cnf']['session_exp'] = min(
                    claims.get('exp', get_timestamp() + 3600),
                    get_timestamp() + 600  # 10 minutes
                )
        
        # Encode header and payload
        header_b64 = base64url_encode(json.dumps(header).encode())
        payload_b64 = base64url_encode(json.dumps(claims).encode())
        
        # Create signing input
        signing_input = f"{header_b64}.{payload_b64}".encode()
        
        # Sign with Dilithium
        signature = self.sig.sign(issuer_sk, signing_input)
        signature_b64 = base64url_encode(signature)
        
        # Return complete JWT
        return f"{header_b64}.{payload_b64}.{signature_b64}"
    
    def verify_id_token(self, token: str, issuer_pk: bytes) -> Dict[str, Any]:
        """
        Verify a JWT and return its claims.
        
        Args:
            token: JWT string
            issuer_pk: Issuer's Dilithium public key
        
        Returns:
            dict: Verified claims
        
        Raises:
            ValueError: If token is invalid
        """
        # Split token
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        
        header_b64, payload_b64, signature_b64 = parts
        
        # Decode header
        header = json.loads(base64url_decode(header_b64))
        if header.get('alg') != 'DILITHIUM3':
            raise ValueError(f"Unsupported algorithm: {header.get('alg')}")
        
        # Verify signature
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = base64url_decode(signature_b64)
        
        if not self.sig.verify(issuer_pk, signing_input, signature):
            raise ValueError("Invalid signature")
        
        # Decode payload
        claims = json.loads(base64url_decode(payload_b64))
        
        # Check expiration
        if 'exp' in claims and get_timestamp() >= claims['exp']:
            raise ValueError("Token expired")
        
        return claims
    
    def extract_client_pubkey_from_token(self, token: str) -> Optional[bytes]:
        """
        Extract client's ephemeral public key from token (without verification).
        
        Args:
            token: JWT string
        
        Returns:
            bytes: Client's ephemeral public key, or None
        """
        try:
            # Split and decode payload
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            payload = json.loads(base64url_decode(parts[1]))
            
            # Extract from cnf claim
            if 'cnf' in payload and 'jwk' in payload['cnf']:
                return extract_pubkey_from_jwk(payload['cnf']['jwk'])
            
            return None
        except:
            return None
