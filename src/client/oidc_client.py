"""
OIDC Client Implementation

Client for performing OpenID Connect authentication flows.
"""

from typing import Dict, Any, Optional
from oidc.jwt_handler import PQJWT
from pop.client import PoPClient
from utils.helpers import generate_random_string


class OIDCClient:
    """
    OpenID Connect Client
    
    Manages the client side of the OIDC authentication flow.
    """
    
    def __init__(
        self,
        client_id: str,
        redirect_uri: str,
        auth_server_url: str,
        client_ephemeral_sk: bytes
    ):
        """
        Initialize OIDC client.
        
        Args:
            client_id: Client identifier
            redirect_uri: Redirect URI for authorization responses
            auth_server_url: Authorization server base URL
            client_ephemeral_sk: Client's ephemeral secret key (from KEMTLS)
        """
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.auth_server_url = auth_server_url
        self.client_ephemeral_sk = client_ephemeral_sk
        
        self.pop_client = PoPClient(client_ephemeral_sk)
        self.jwt_handler = PQJWT()
        
        self.id_token: Optional[str] = None
        self.access_token: Optional[str] = None
    
    def create_authorization_url(
        self,
        scope: str = "openid profile email",
        state: Optional[str] = None,
        nonce: Optional[str] = None
    ) -> str:
        """
        Create authorization URL for user to visit.
        
        Args:
            scope: Requested scopes
            state: State parameter for CSRF protection
            nonce: Nonce for replay protection
        
        Returns:
            str: Authorization URL
        """
        if not state:
            state = generate_random_string(16)
        if not nonce:
            nonce = generate_random_string(16)
        
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': scope,
            'state': state,
            'nonce': nonce
        }
        
        query_string = '&'.join(f"{k}={v}" for k, v in params.items())
        return f"{self.auth_server_url}/authorize?{query_string}"
    
    def exchange_code_for_tokens(
        self,
        code: str
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for tokens.
        
        Args:
            code: Authorization code from server
        
        Returns:
            dict: Token response containing id_token and access_token
        """
        # In real implementation, this would make HTTP request to token endpoint
        # For now, we return a mock response
        return {
            'access_token': 'mock_access_token',
            'token_type': 'Bearer',
            'id_token': 'mock_id_token',
            'expires_in': 3600
        }
    
    def store_tokens(self, token_response: Dict[str, Any]):
        """Store received tokens."""
        self.id_token = token_response.get('id_token')
        self.access_token = token_response.get('access_token')
    
    def create_pop_proof_for_resource(
        self,
        challenge: Dict[str, Any]
    ) -> str:
        """
        Create PoP proof for accessing protected resource.
        
        Args:
            challenge: Challenge from resource server
        
        Returns:
            str: PoP proof (base64url-encoded signature)
        """
        if not self.id_token:
            raise ValueError("No ID token available")
        
        return self.pop_client.create_pop_proof(challenge, self.id_token)
