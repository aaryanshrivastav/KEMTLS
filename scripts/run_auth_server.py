"""
Run Authorization Server
Role: Start Authorization Server

Workflow:
1. Load keys from keys/ directory
2. Initialize KEMTLS server
3. Start Flask app
4. Listen on port 5000
"""

import os
import sys
import argparse

# Add src to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from servers.auth_server import AuthorizationServer


def load_keys(keys_dir):
    """Load pre-generated keys from keys/ directory"""
    print("\n1. Loading keys...")
    
    # Load Kyber keypair
    kyber_pk_path = os.path.join(keys_dir, "auth_server_kyber_pk.bin")
    kyber_sk_path = os.path.join(keys_dir, "auth_server_kyber_sk.bin")
    
    if not os.path.exists(kyber_pk_path) or not os.path.exists(kyber_sk_path):
        print("   ⚠️  Kyber keys not found. Run: python scripts/generate_keys.py")
        return None, None, None, None
    
    with open(kyber_pk_path, "rb") as f:
        kyber_pk = f.read()
    with open(kyber_sk_path, "rb") as f:
        kyber_sk = f.read()
    print(f"   ✓ Loaded Kyber768 keypair ({len(kyber_pk)} / {len(kyber_sk)} bytes)")
    
    # Load Dilithium keypair
    dilithium_pk_path = os.path.join(keys_dir, "auth_server_dilithium_pk.bin")
    dilithium_sk_path = os.path.join(keys_dir, "auth_server_dilithium_sk.bin")
    
    if not os.path.exists(dilithium_pk_path) or not os.path.exists(dilithium_sk_path):
        print("   ⚠️  Dilithium keys not found. Run: python scripts/generate_keys.py")
        return kyber_pk, kyber_sk, None, None
    
    with open(dilithium_pk_path, "rb") as f:
        dilithium_pk = f.read()
    with open(dilithium_sk_path, "rb") as f:
        dilithium_sk = f.read()
    print(f"   ✓ Loaded ML-DSA-65 keypair ({len(dilithium_pk)} / {len(dilithium_sk)} bytes)")
    
    return kyber_pk, kyber_sk, dilithium_pk, dilithium_sk


def main():
    """Main server startup workflow"""
    parser = argparse.ArgumentParser(description="Run Authorization Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")
    parser.add_argument("--generate-keys", action="store_true", help="Generate keys if missing")
    args = parser.parse_args()
    
    print("=" * 60)
    print("Authorization Server Startup")
    print("=" * 60)
    
    # Load keys
    keys_dir = os.path.join(ROOT_DIR, "keys")
    kyber_pk, kyber_sk, dilithium_pk, dilithium_sk = load_keys(keys_dir)
    
    # Generate keys if requested and missing
    if args.generate_keys and (kyber_pk is None or dilithium_pk is None):
        print("\n   Generating missing keys...")
        from crypto.kyber_kem import KyberKEM
        from crypto.dilithium_sig import DilithiumSignature
        
        if not os.path.exists(keys_dir):
            os.makedirs(keys_dir)
        
        if kyber_pk is None:
            kem = KyberKEM()
            kyber_pk, kyber_sk = kem.generate_keypair()
            with open(os.path.join(keys_dir, "auth_server_kyber_pk.bin"), "wb") as f:
                f.write(kyber_pk)
            with open(os.path.join(keys_dir, "auth_server_kyber_sk.bin"), "wb") as f:
                f.write(kyber_sk)
            print("   ✓ Generated Kyber768 keypair")
        
        if dilithium_pk is None:
            sig = DilithiumSignature()
            dilithium_pk, dilithium_sk = sig.generate_keypair()
            with open(os.path.join(keys_dir, "auth_server_dilithium_pk.bin"), "wb") as f:
                f.write(dilithium_pk)
            with open(os.path.join(keys_dir, "auth_server_dilithium_sk.bin"), "wb") as f:
                f.write(dilithium_sk)
            print("   ✓ Generated ML-DSA-65 keypair")
    
    if kyber_pk is None or dilithium_pk is None:
        print("\n❌ Cannot start server without keys. Run with --generate-keys or:")
        print("   python scripts/generate_keys.py")
        return
    
    # Initialize server
    print("\n2. Initializing KEMTLS Authorization Server...")
    issuer_url = f"http://{args.host if args.host != '0.0.0.0' else 'localhost'}:{args.port}"
    server = AuthorizationServer(issuer_url=issuer_url)
    
    # Override keys with loaded ones
    server.server_lt_pk = kyber_pk
    server.server_lt_sk = kyber_sk
    server.issuer_pk = dilithium_pk
    server.issuer_sk = dilithium_sk
    server.token_endpoint.issuer_sk = dilithium_sk
    server.token_endpoint.issuer_pk = dilithium_pk
    
    print("   ✓ KEMTLS session initialized")
    print("   ✓ OIDC endpoints configured")
    
    # Start Flask app
    print("\n3. Starting Flask application...")
    print(f"   • Issuer URL: {issuer_url}")
    print(f"   • Host: {args.host}")
    print(f"   • Port: {args.port}")
    
    print("\n" + "=" * 60)
    print("✅ Authorization Server Ready")
    print("=" * 60)
    print("\nEndpoints:")
    print(f"  • Discovery: {issuer_url}/.well-known/openid-configuration")
    print(f"  • Authorize: {issuer_url}/authorize")
    print(f"  • Token:     {issuer_url}/token")
    print("\nPress Ctrl+C to stop\n")
    
    # Run server (blocking)
    server.run(host=args.host, port=args.port)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Authorization Server stopped")
        sys.exit(0)
