"""
OIDC Discovery Endpoint
"""

from typing import Dict, Any

class DiscoveryEndpoint:
    def __init__(self, issuer_url: str):
        self.issuer_url = issuer_url
    
    def get_configuration(self) -> Dict[str, Any]:
        return {
            'issuer': self.issuer_url,
            'authorization_endpoint': f'{self.issuer_url}/authorize',
            'token_endpoint': f'{self.issuer_url}/token',
            'userinfo_endpoint': f'{self.issuer_url}/userinfo',
            'response_types_supported': ['code'],
            'grant_types_supported': ['authorization_code'],
            'scopes_supported': ['openid', 'profile', 'email'],
            'id_token_signing_alg_values_supported': ['DILITHIUM3'],
            'kemtls_supported': True
        }
