"""
OIDC Token Endpoint

Exchanges authorization codes for ID tokens and access tokens.
"""

from typing import Dict, Any
from .jwt_handler import PQJWT
from utils.helpers import get_timestamp


class TokenEndpoint:
    """Token endpoint implementation."""
    
    def __init__(self, issuer_url: str, issuer_sk: bytes, issuer_pk: bytes):
        self.issuer_url = issuer_url
        self.issuer_sk = issuer_sk
        self.issuer_pk = issuer_pk
        self.jwt_handler = PQJWT()
    
    def handle_token_request(
        self,
        grant_type: str,
        code: str,
        code_data: Dict[str, Any],
        client_ephemeral_pk: bytes,
        session_id: str,
        session_key: bytes
    ) -> Dict[str, Any]:
        """Handle token request."""
        if grant_type != 'authorization_code':
            return {'error': 'unsupported_grant_type'}
        
        # Create ID token claims
        claims = {
            'iss': self.issuer_url,
            'sub': code_data['user_id'],
            'aud': code_data['client_id'],
            'iat': get_timestamp(),
            'exp': get_timestamp() + 3600,
        }
        
        if code_data.get('nonce'):
            claims['nonce'] = code_data['nonce']
        
        # Add scope-based claims
        if 'profile' in code_data.get('scope', ''):
            claims['name'] = f"User {code_data['user_id']}"
        if 'email' in code_data.get('scope', ''):
            claims['email'] = f"{code_data['user_id']}@example.com"
            claims['email_verified'] = True
        
        # Create ID token with PoP binding
        id_token = self.jwt_handler.create_id_token(
            claims,
            self.issuer_sk,
            self.issuer_pk,
            client_ephemeral_pk,
            session_key,
            session_id
        )
        
        return {
            'access_token': id_token,
            'token_type': 'Bearer',
            'id_token': id_token,
            'expires_in': 3600,
            'scope': code_data.get('scope', 'openid')
        }
