"""
Resource Server

Protects resources using PoP-bound tokens.
"""

from flask import Flask, request, jsonify
from oidc.jwt_handler import PQJWT
from pop.server import ProofOfPossession
from utils.helpers import is_expired

class ResourceServer:
    def __init__(self, issuer_pk: bytes):
        self.app = Flask(__name__)
        self.issuer_pk = issuer_pk
        self.jwt_handler = PQJWT()
        self.pop = ProofOfPossession()
        self.setup_routes()
    
    def setup_routes(self):
        @self.app.route('/api/userinfo')
        def userinfo():
            # Get token
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'unauthorized'}), 401
            
            token = auth_header[7:]
            
            try:
                # Validate token
                claims = self.jwt_handler.verify_id_token(token, self.issuer_pk)
                
                # Check PoP binding
                if 'cnf' not in claims:
                    return jsonify({'error': 'no_pop_binding'}), 401
                
                # Issue challenge
                challenge = self.pop.generate_challenge()
                return jsonify({'pop_required': True, 'challenge': challenge})
            
            except Exception as e:
                return jsonify({'error': str(e)}), 401
    
    def run(self, host='0.0.0.0', port=5001):
        print(f"Resource Server running on http://{host}:{port}")
        self.app.run(host=host, port=port)

if __name__ == '__main__':
    # Would load issuer public key from config
    from crypto.dilithium_sig import DilithiumSignature
    sig = DilithiumSignature()
    pk, sk = sig.generate_keypair()
    
    server = ResourceServer(pk)
    server.run()
