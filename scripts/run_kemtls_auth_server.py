"""
Authorization Server Implementation over KEMTLS

Endpoints:
- /authorize: Mock authorize
- /token: Code + PKCE -> Session-bound JWT
"""

import os
import json
import sys
import threading
from pathlib import Path
from typing import Dict
from urllib.parse import parse_qs
from flask import Flask, request, jsonify, g

# Ensure src in path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from kemtls.tcp_server import KEMTLSTCPServer
from utils.encoding import base64url_decode, base64url_encode
from crypto.ml_dsa import MLDSA65
from utils.helpers import get_timestamp, generate_random_string


# Global storage for mock authorization codes
AUTH_CODES: Dict[str, dict] = {}


def load_pdk_key_id(base_dir: Path, identity: str) -> str | None:
    manifest_path = base_dir / 'pdk' / 'pdk_manifest.json'
    if not os.path.exists(manifest_path):
        return None

    with open(manifest_path) as f:
        manifest = json.load(f)

    for entry in manifest:
        if entry.get('identity') == identity:
            return entry.get('key_id')

    return None


def create_auth_app(config: dict):
    app = Flask(__name__)
    
    @app.route('/authorize')
    def authorize():
        # Mock authorization: generate a code
        code = generate_random_string(16)
        client_id = request.args.get('client_id')
        code_challenge = request.args.get('code_challenge')
        
        AUTH_CODES[code] = {
            'client_id': client_id,
            'code_challenge': code_challenge,
            'user_id': 'user-1'
        }
        return jsonify({'code': code})

    @app.route('/token', methods=['POST'])
    def token():
        # 1. Fetch Session Binding from KEMTLS Context
        session = request.environ.get('kemtls.session')
        if not session:
            return jsonify({'error': 'no_kemtls_session'}), 401
            
        binding_id = session.session_binding_id
        
        # 2. Extract Token Request Details
        raw_body = request.get_data(as_text=True)
        parsed = parse_qs(raw_body, keep_blank_values=True) if raw_body else {}
        form_data = {k: v[0] for k, v in parsed.items() if v}
        if not form_data:
            form_data = request.form.to_dict(flat=True)

        grant_type = form_data.get('grant_type')
        if grant_type == 'authorization_code':
            code = form_data.get('code')
            verifier = form_data.get('code_verifier')
            
            if code not in AUTH_CODES:
                return jsonify({'error': 'invalid_code'}), 400
                
            code_data = AUTH_CODES.pop(code)
            
            # Simple PKCE check S256? (Optional for demo)
            # if code_data['code_challenge'] != verifier: ...
            
        elif grant_type == 'refresh_token':
            # Simplified rotation for demo
            pass
        else:
            return jsonify({
                'error': 'unsupported_grant_type',
                'observed_grant_type': grant_type,
                'raw_body': raw_body,
                'content_type': request.headers.get('Content-Type', ''),
            }), 400

        # 3. Issue Session-Bound JWT
        now = get_timestamp()
        claims = {
            'iss': 'auth-server',
            'sub': 'user-1',
            'iat': now,
            'exp': now + 3600,
            'session_binding_id': binding_id
        }
        
        # Sign using ML-DSA
        jwt_sk = base64url_decode(config['jwt_signing_sk'])
        token_body = json.dumps(claims).encode('utf-8')
        signature = MLDSA65.sign(jwt_sk, token_body)
        
        access_token = f"{base64url_encode(token_body)}.{base64url_encode(signature)}"
        
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'refresh_token': 'mock-refresh-token'
        })

    @app.route('/resource')
    @app.route('/userinfo')
    def resource():
        session = request.environ.get('kemtls.session')
        if not session:
            return jsonify({'error': 'no_kemtls_session'}), 401

        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'missing_token'}), 401

        token = auth_header.split(' ')[1]
        try:
            parts = token.split('.')
            if len(parts) != 2:
                raise ValueError('Malformed token')

            body_bytes = base64url_decode(parts[0])
            signature = base64url_decode(parts[1])
            jwt_pk = base64url_decode(config['jwt_signing_pk'])
            if not MLDSA65.verify(jwt_pk, body_bytes, signature):
                raise ValueError('Invalid signature')

            claims = json.loads(body_bytes.decode('utf-8'))
            if get_timestamp() > claims.get('exp', 0):
                raise ValueError('Token expired')

            token_binding_id = claims.get('session_binding_id')
            current_binding_id = session.session_binding_id
            if token_binding_id != current_binding_id:
                return jsonify({'error': 'binding_mismatch', 'details': 'TBT violation'}), 403

        except Exception as e:
            return jsonify({'error': 'invalid_token', 'details': str(e)}), 401

        return jsonify({
            'status': 'access_granted',
            'user': claims.get('sub'),
            'binding_id': session.session_binding_id,
            'message': 'Resource access granted on matched KEMTLS session binding.'
        })

    return app


def main():
    base_dir = Path(__file__).parent.parent / 'keys'
    config_path = base_dir / 'auth_server' / 'as_config.json'
    if not os.path.exists(config_path):
        print("Config not found. Run bootstrap_ca.py first.")
        return
        
    with open(config_path) as f:
        config = json.load(f)
        
    as_lt_sk = base64url_decode(config['longterm_sk'])
    as_cert = config['certificate']
    as_pdk_key_id = load_pdk_key_id(base_dir, 'auth-server')
    print(f"Auth server PDK key id: {as_pdk_key_id}")
    
    app = create_auth_app(config)
    server = KEMTLSTCPServer(
        app=app,
        server_identity='auth-server',
        server_lt_sk=as_lt_sk,
        cert=as_cert,
        pdk_key_id=as_pdk_key_id,
        host='127.0.0.1',
        port=4433
    )
    
    print("Starting Auth Server on port 4433...")
    server.start()


if __name__ == "__main__":
    main()
