"""
OIDC Authorization Endpoint

Handles authorization requests and issues authorization codes.
"""

from typing import Dict, Any, Optional
from utils.helpers import generate_random_string, get_timestamp


class AuthorizationEndpoint:
    """Authorization endpoint implementation."""
    
    def __init__(self):
        self.authorization_codes = {}
    
    def handle_authorize_request(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: str,
        nonce: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Handle authorization request."""
        # Validate
        if not client_id or not redirect_uri:
            return {'error': 'invalid_request'}
        
        # Check authentication
        if not user_id:
            return {'auth_required': True}
        
        # Generate authorization code
        code = generate_random_string(32)
        
        # Store with 10-minute expiry
        self.authorization_codes[code] = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'user_id': user_id,
            'nonce': nonce,
            'issued_at': get_timestamp(),
            'expires_at': get_timestamp() + 600
        }
        
        return {
            'code': code,
            'state': state
        }
    
    def validate_code(self, code: str, client_id: str, redirect_uri: str) -> Optional[Dict]:
        """Validate and consume authorization code."""
        if code not in self.authorization_codes:
            return None
        
        code_data = self.authorization_codes[code]
        
        # Verify match
        if (code_data['client_id'] != client_id or 
            code_data['redirect_uri'] != redirect_uri):
            return None
        
        # Check expiration
        if get_timestamp() > code_data['expires_at']:
            del self.authorization_codes[code]
            return None
        
        # Delete (one-time use)
        del self.authorization_codes[code]
        
        return code_data
