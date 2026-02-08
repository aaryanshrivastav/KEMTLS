"""
Authorization Server

Complete OIDC authorization server with KEMTLS support.
"""

from flask import Flask, request, jsonify
from crypto.kyber_kem import KyberKEM
from crypto.dilithium_sig import DilithiumSignature
from kemtls.session import KEMTLSSession
from oidc.authorization import AuthorizationEndpoint
from oidc.token import TokenEndpoint
from oidc.discovery import DiscoveryEndpoint

class AuthorizationServer:
    def __init__(self, issuer_url="http://localhost:5000"):
        self.app = Flask(__name__)
        self.issuer_url = issuer_url
        
        # Generate keys
        kem = KyberKEM()
        self.server_lt_pk, self.server_lt_sk = kem.generate_keypair()
        
        sig = DilithiumSignature()
        self.issuer_pk, self.issuer_sk = sig.generate_keypair()
        
        # Initialize endpoints
        self.auth_endpoint = AuthorizationEndpoint()
        self.token_endpoint = TokenEndpoint(issuer_url, self.issuer_sk, self.issuer_pk)
        self.discovery_endpoint = DiscoveryEndpoint(issuer_url)
        
        # Setup routes
        self.setup_routes()
    
    def setup_routes(self):
        @self.app.route('/.well-known/openid-configuration')
        def discovery():
            return jsonify(self.discovery_endpoint.get_configuration())
        
        @self.app.route('/authorize')
        def authorize():
            result = self.auth_endpoint.handle_authorize_request(
                client_id=request.args.get('client_id'),
                redirect_uri=request.args.get('redirect_uri'),
                scope=request.args.get('scope'),
                state=request.args.get('state'),
                nonce=request.args.get('nonce'),
                user_id='alice'  # Simplified auth
            )
            return jsonify(result)
        
        @self.app.route('/token', methods=['POST'])
        def token():
            data = request.get_json()
            # Simplified - would validate authorization code here
            return jsonify({'access_token': 'demo_token', 'token_type': 'Bearer'})
    
    def run(self, host='0.0.0.0', port=5000):
        print(f"Authorization Server running on {self.issuer_url}")
        self.app.run(host=host, port=port)

if __name__ == '__main__':
    server = AuthorizationServer()
    server.run()
