"""
Post-Quantum OIDC Client using KEMTLS

Implements the Authorization Code Flow with PKCE (Proof Key for Code Exchange)
over KEMTLS infrastructure. Supports access/refresh token management and 
telemetry collection.
"""

import hashlib
import base64
import time
from typing import Dict, Any, Optional, List
from client.kemtls_http_client import KEMTLSHttpClient
from utils.helpers import generate_random_string


class OIDCClient:
    """
    OIDC client implementation using KEMTLS.
    """
    
    def __init__(
        self,
        http_client: KEMTLSHttpClient,
        client_id: str,
        issuer_url: str,
        redirect_uri: str
    ):
        """
        Initialize the OIDC client.
        
        Args:
            http_client: KEMTLS-capable HTTP client
            client_id: Client identifier
            issuer_url: OIDC issuer base URL
            redirect_uri: Redirect URI for authorization
        """
        self.http_client = http_client
        self.client_id = client_id
        self.issuer_url = issuer_url
        self.redirect_uri = redirect_uri
        
        # State and tokens
        self.code_verifier: Optional[str] = None
        self.code_challenge: Optional[str] = None
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.id_token: Optional[str] = None
        
        # Telemetry storage
        self.telemetry = {
            'handshakes': [],
            'tokens': [],
            'refresh_events': []
        }

    def start_auth(self, scope: str = "openid profile email") -> str:
        """
        Start the authorization flow.
        Generates PKCE verifier/challenge and returns the auth URL.
        """
        # PKCE: Proof Key for Code Exchange (S256)
        # 1. Generate code_verifier (random URL-safe string, 43-128 chars)
        self.code_verifier = generate_random_string(64)
        
        # 2. Derive code_challenge = Base64url(SHA256(code_verifier))
        sha256_hash = hashlib.sha256(self.code_verifier.encode('utf-8')).digest()
        self.code_challenge = base64.urlsafe_b64encode(sha256_hash).decode('ascii').rstrip('=')
        
        # 3. Construct Authorization URL
        params = {
            'client_id': self.client_id,
            'response_type': 'code',
            'scope': scope,
            'redirect_uri': self.redirect_uri,
            'code_challenge': self.code_challenge,
            'code_challenge_method': 'S256',
            'state': generate_random_string(16)
        }
        
        query = "&".join([f"{k}={v}" for k, v in params.items()])
        auth_url = f"{self.issuer_url}/authorize?{query}"
        
        return auth_url

    def exchange_code(self, code: str) -> Dict[str, Any]:
        """
        Exchange the authorization code for tokens.
        """
        if not self.code_verifier:
            raise ValueError("No code_verifier found - call start_auth first.")
            
        token_url = f"{self.issuer_url}/token"
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id,
            'code_verifier': self.code_verifier
        }
        
        start_time = time.perf_counter()
        resp = self.http_client.post(token_url, data=data)
        duration = (time.perf_counter() - start_time) * 1000  # in ms
        
        if resp.get('status') != 200:
            raise ValueError(f"Token exchange failed (Status {resp.get('status')}): {resp.get('body')}")
            
        # Parse Response
        token_data = resp.get('body', {})
        self.access_token = token_data.get('access_token')
        self.refresh_token = token_data.get('refresh_token')
        self.id_token = token_data.get('id_token')
        
        # Capture Telemetry
        metadata = resp.get('kemtls_metadata', {})
        self.telemetry['handshakes'].append({
            'mode': metadata.get('mode'),
            'duration_ms': duration,
            'session_id': metadata.get('session_id')
        })
        
        if self.access_token:
            self.telemetry['tokens'].append({
                'type': 'access',
                'size_bytes': len(self.access_token),
                'binding_claim': metadata.get('session_binding_id')
            })
            
        return token_data

    def call_api(self, api_url: str) -> Dict[str, Any]:
        """
        Perform an authenticated API call.
        """
        if not self.access_token:
            raise ValueError("No access token available - exchange code first.")
            
        headers = {
            'Authorization': f"Bearer {self.access_token}"
        }
        
        resp = self.http_client.get(api_url, headers=headers)
        return resp

    def refresh(self) -> Dict[str, Any]:
        """
        Refresh the access token.
        """
        if not self.refresh_token:
            raise ValueError("No refresh token available.")
            
        token_url = f"{self.issuer_url}/token"
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token,
            'client_id': self.client_id
        }
        
        resp = self.http_client.post(token_url, data=data)
        
        if resp.get('status') != 200:
            raise ValueError(f"Token refresh failed: {resp.get('body')}")
            
        token_data = resp.get('body', {})
        self.access_token = token_data.get('access_token')
        self.refresh_token = token_data.get('refresh_token')
        
        self.telemetry['refresh_events'].append({
            'timestamp': time.time(),
            'status': 'success'
        })
        
        return token_data

    def replay_attack(self, api_url: str) -> Dict[str, Any]:
        """
        Perform a replay attack demonstration.
        Tries to use a token from one session on a new session.
        """
        if not self.access_token:
            raise ValueError("No token to replay - generate one first.")
            
        # Create a FRESH http client (new session)
        new_client = KEMTLSHttpClient(
            ca_pk=self.http_client.ca_pk,
            pdk_store=self.http_client.pdk_store,
            expected_identity=self.http_client.expected_identity,
            mode=self.http_client.mode
        )
        
        headers = {
            'Authorization': f"Bearer {self.access_token}"
        }
        
        # This SHOULD fail on the server due to binding mismatch
        # server_binding_id in token != current session_id
        print("Demonstrating Replay Attack: Using bound token in new session...")
        resp = new_client.get(api_url, headers=headers)
        
        return resp

    def get_telemetry(self) -> Dict[str, Any]:
        """Return the collected telemetry."""
        return self.telemetry
