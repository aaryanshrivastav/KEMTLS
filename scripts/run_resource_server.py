"""
Run Resource Server
Role: Start Resource Server

Workflow:
1. Load issuer public key from keys/ directory
2. Initialize PoP verifier
3. Start Flask app
4. Listen on port 5001
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

from servers.resource_server import ResourceServer


def load_issuer_public_key(keys_dir):
    """Load issuer public key from keys/ directory"""
    print("\n1. Loading issuer public key...")
    
    dilithium_pk_path = os.path.join(keys_dir, "auth_server_dilithium_pk.bin")
    
    if not os.path.exists(dilithium_pk_path):
        print("   ⚠️  Issuer public key not found. Run: python scripts/generate_keys.py")
        return None
    
    with open(dilithium_pk_path, "rb") as f:
        issuer_pk = f.read()
    
    print(f"   ✓ Loaded issuer ML-DSA-65 public key ({len(issuer_pk)} bytes)")
    return issuer_pk


def main():
    """Main server startup workflow"""
    parser = argparse.ArgumentParser(description="Run Resource Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5001, help="Port to listen on (default: 5001)")
    parser.add_argument("--issuer-key", help="Path to issuer public key file")
    args = parser.parse_args()
    
    print("=" * 60)
    print("Resource Server Startup")
    print("=" * 60)
    
    # Load issuer public key
    if args.issuer_key:
        print(f"\n1. Loading issuer public key from {args.issuer_key}...")
        with open(args.issuer_key, "rb") as f:
            issuer_pk = f.read()
        print(f"   ✓ Loaded issuer public key ({len(issuer_pk)} bytes)")
    else:
        keys_dir = os.path.join(ROOT_DIR, "keys")
        issuer_pk = load_issuer_public_key(keys_dir)
    
    if issuer_pk is None:
        print("\n❌ Cannot start server without issuer public key.")
        print("   Run: python scripts/generate_keys.py")
        print("   Or provide: --issuer-key <path>")
        return
    
    # Initialize PoP verifier
    print("\n2. Initializing PoP verifier...")
    server = ResourceServer(issuer_pk=issuer_pk)
    print("   ✓ JWT handler configured")
    print("   ✓ PoP verifier initialized")
    
    # Start Flask app
    print("\n3. Starting Flask application...")
    host_display = "localhost" if args.host == "0.0.0.0" else args.host
    print(f"   • Host: {args.host}")
    print(f"   • Port: {args.port}")
    
    print("\n" + "=" * 60)
    print("✅ Resource Server Ready")
    print("=" * 60)
    print("\nEndpoints:")
    print(f"  • User Info: http://{host_display}:{args.port}/api/userinfo")
    print("\nProtected Resources:")
    print(f"  • Requires: Valid PoP-bound access token")
    print(f"  • Issuer:   Configured with loaded public key")
    print("\nPress Ctrl+C to stop\n")
    
    # Run server (blocking)
    server.run(host=args.host, port=args.port)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Resource Server stopped")
        sys.exit(0)
