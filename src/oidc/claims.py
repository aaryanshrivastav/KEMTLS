"""
OIDC Claims Processing
"""

from typing import Dict, Any, List

class ClaimsProcessor:
    def __init__(self):
        self.users = {
            'alice': {'sub': 'alice', 'name': 'Alice', 'email': 'alice@example.com'},
            'bob': {'sub': 'bob', 'name': 'Bob', 'email': 'bob@example.com'}
        }
    
    def get_user_claims(self, user_id: str, scopes: List[str]) -> Dict[str, Any]:
        user = self.users.get(user_id, {})
        claims = {'sub': user_id}
        
        if 'profile' in scopes and 'name' in user:
            claims['name'] = user['name']
        if 'email' in scopes and 'email' in user:
            claims['email'] = user['email']
        
        return claims
