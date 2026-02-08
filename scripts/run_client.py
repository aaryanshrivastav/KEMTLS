"""
Run Client Demonstration
Role: Run client demonstration

Workflow:
1. Perform KEMTLS handshake with auth server
2. Request authorization
3. Exchange code for token
4. Access protected resource with PoP
5. Display results
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

from crypto.kyber_kem import KyberKEM
from crypto.dilithium_sig import DilithiumSignature
from kemtls.handshake import KEMTLSHandshake
from client.oidc_client import OIDCClient
from pop.client import PoPClient


def print_step(step_num, title):
    """Print step header"""
    print(f"\n{'=' * 60}")
    print(f"Step {step_num}: {title}")
    print('=' * 60)


def step1_kemtls_handshake(server_lt_pk):
    """Perform KEMTLS handshake"""
    print_step(1, "KEMTLS Handshake")
    
    print("\n   Initializing client KEMTLS...")
    client = KEMTLSHandshake(is_server=False)
    
    # Simulate server hello (in real scenario, this comes from network)
    print("   Creating server hello...")
    server = KEMTLSHandshake(is_server=True)
    
    # Load actual server secret key for simulation
    keys_dir = os.path.join(ROOT_DIR, "keys")
    kyber_sk_path = os.path.join(keys_dir, "auth_server_kyber_sk.bin")
    with open(kyber_sk_path, "rb") as f:
        server_lt_sk = f.read()
    
    server_hello = server.server_init_handshake(server_lt_sk, server_lt_pk)
    print(f"   ✓ Received server hello ({len(server_hello)} bytes)")
    
    # Client processes server hello
    print("   Processing server hello...")
    client_kex, client_eph_pk = client.client_process_server_hello(
        server_hello,
        trusted_longterm_pk=server_lt_pk
    )
    print(f"   ✓ Generated client key exchange ({len(client_kex)} bytes)")
    
    # Server processes client key exchange
    print("   Server processing client key exchange...")
    server_keys = server.server_process_client_key_exchange(client_kex)
    client_keys = client.get_session_keys()
    
    # Verify key agreement
    assert server_keys == client_keys, "Key agreement failed!"
    print("   ✓ KEMTLS handshake complete")
    print(f"   ✓ Session keys established")
    
    return client_keys, client_eph_pk


def step2_request_authorization(auth_server_url, client_id, redirect_uri, client_eph_sk):
    """Request authorization"""
    print_step(2, "Request Authorization")
    
    print(f"\n   Auth Server: {auth_server_url}")
    print(f"   Client ID:   {client_id}")
    print(f"   Redirect:    {redirect_uri}")
    
    # Create OIDC client
    client = OIDCClient(
        client_id=client_id,
        redirect_uri=redirect_uri,
        auth_server_url=auth_server_url,
        client_ephemeral_sk=client_eph_sk
    )
    
    # Generate authorization URL
    auth_url = client.create_authorization_url(
        scope="openid profile email",
        state="demo_state_123",
        nonce="demo_nonce_456"
    )
    
    print(f"\n   Authorization URL:")
    print(f"   {auth_url}")
    print("\n   ✓ Authorization request created")
    
    # Simulate authorization (in real scenario, user visits URL and approves)
    print("\n   [Simulated] User approves authorization...")
    auth_code = "demo_auth_code_xyz"
    print(f"   ✓ Received authorization code: {auth_code}")
    
    return client, auth_code


def step3_exchange_token(client, auth_code):
    """Exchange code for token"""
    print_step(3, "Exchange Code for Token")
    
    print(f"\n   Authorization code: {auth_code}")
    
    # In real scenario, this would make HTTP request to token endpoint
    print("   [Simulated] POST to /token endpoint...")
    
    # Load actual server Dilithium keys for simulation
    keys_dir = os.path.join(ROOT_DIR, "keys")
    dilithium_pk_path = os.path.join(keys_dir, "auth_server_dilithium_pk.bin")
    dilithium_sk_path = os.path.join(keys_dir, "auth_server_dilithium_sk.bin")
    
    with open(dilithium_pk_path, "rb") as f:
        issuer_pk = f.read()
    with open(dilithium_sk_path, "rb") as f:
        issuer_sk = f.read()
    
    # Simulate token response
    from oidc.jwt_handler import PQJWT
    jwt = PQJWT()
    
    # Create ID token with PoP binding
    claims = {
        "iss": "http://localhost:5000",
        "sub": "alice",
        "aud": "demo_client",
        "exp": 1999999999,
        "iat": 1000000000,
        "nonce": "demo_nonce_456",
        "cnf": {
            "kid": "client_eph_pk_hash"
        }
    }
    
    id_token = jwt.create_id_token(claims, issuer_sk, issuer_pk)
    access_token = "demo_access_token_" + "a" * 50
    
    print(f"   ✓ Received ID token ({len(id_token)} bytes)")
    print(f"   ✓ Received access token ({len(access_token)} chars)")
    print(f"   ✓ Token includes PoP binding (cnf claim)")
    
    return id_token, access_token, issuer_pk


def step4_access_resource(access_token, client_eph_pk, client_eph_sk, resource_url):
    """Access protected resource with PoP"""
    print_step(4, "Access Protected Resource with PoP")
    
    print(f"\n   Resource URL: {resource_url}")
    print(f"   Access token: {access_token[:30]}...")
    
    # Create PoP client
    pop_client = PoPClient(client_eph_sk)
    
    # Simulate resource server challenge
    print("\n   [Simulated] Resource server issues PoP challenge...")
    from pop.server import ProofOfPossession
    pop_server = ProofOfPossession()
    challenge = pop_server.generate_challenge()
    print(f"   ✓ Received challenge nonce: {challenge['nonce'][:30]}...")
    print(f"   ✓ Challenge timestamp: {challenge['timestamp']}")
    
    # Generate PoP proof
    print("\n   Generating PoP proof...")
    proof = pop_client.create_pop_proof(
        challenge=challenge,
        token=access_token
    )
    print(f"   ✓ Generated proof ({len(proof)} bytes)")
    
    # Verify PoP (simulating resource server)
    print("\n   [Simulated] Resource server verifies PoP...")
    is_valid = pop_server.verify_pop_response(
        challenge=challenge,
        proof=proof,
        client_eph_pk=client_eph_pk,
        token=access_token
    )
    
    if is_valid:
        print("   ✓ PoP verification successful")
        print("   ✓ Access granted to protected resource")
        return True
    else:
        print("   ✗ PoP verification failed")
        return False


def step5_display_results(success):
    """Display final results"""
    print_step(5, "Results")
    
    if success:
        print("\n   ✅ Authentication Flow Complete")
        print("\n   Summary:")
        print("   • KEMTLS handshake:         ✓ Established")
        print("   • Authorization:            ✓ Granted")
        print("   • Token exchange:           ✓ Successful")
        print("   • PoP binding:              ✓ Verified")
        print("   • Resource access:          ✓ Allowed")
        print("\n   🎉 Full PQ-OIDC+KEMTLS flow demonstrated successfully!")
    else:
        print("\n   ⚠️  Authentication Flow Incomplete")
        print("\n   Some steps failed. Check logs above.")


def main():
    """Main client demonstration"""
    parser = argparse.ArgumentParser(description="Run OIDC+KEMTLS Client Demo")
    parser.add_argument("--auth-server", default="http://localhost:5000", 
                       help="Auth server URL (default: http://localhost:5000)")
    parser.add_argument("--resource-server", default="http://localhost:5001",
                       help="Resource server URL (default: http://localhost:5001)")
    parser.add_argument("--client-id", default="demo_client",
                       help="Client ID (default: demo_client)")
    parser.add_argument("--redirect-uri", default="http://localhost:8080/callback",
                       help="Redirect URI (default: http://localhost:8080/callback)")
    args = parser.parse_args()
    
    print("=" * 60)
    print("PQ-OIDC + KEMTLS Client Demonstration")
    print("=" * 60)
    print("\nThis script demonstrates the complete authentication flow:")
    print("  1. KEMTLS handshake")
    print("  2. OIDC authorization")
    print("  3. Token exchange")
    print("  4. PoP-bound resource access")
    print("  5. Results display")
    
    try:
        # Load server long-term public key (in real scenario, from discovery)
        keys_dir = os.path.join(ROOT_DIR, "keys")
        kyber_pk_path = os.path.join(keys_dir, "auth_server_kyber_pk.bin")
        
        if not os.path.exists(kyber_pk_path):
            print("\n❌ Error: Server keys not found!")
            print("   Please run: python scripts/generate_keys.py")
            sys.exit(1)
        
        with open(kyber_pk_path, "rb") as f:
            server_lt_pk = f.read()
        print(f"\n✓ Loaded server public key ({len(server_lt_pk)} bytes)")
        
        # Execute workflow
        client_keys, _ = step1_kemtls_handshake(server_lt_pk)
        
        # Generate client ephemeral Dilithium keypair for PoP
        # (In real implementation, this would be generated during initial setup)
        print("\n✓ Generating client ephemeral Dilithium keypair for PoP...")
        sig = DilithiumSignature()
        client_eph_pk, client_eph_sk = sig.generate_keypair()
        print(f"   • Public key:  {len(client_eph_pk)} bytes")
        print(f"   • Secret key:  {len(client_eph_sk)} bytes")
        
        client, auth_code = step2_request_authorization(
            args.auth_server, 
            args.client_id,
            args.redirect_uri,
            client_eph_sk
        )
        
        id_token, access_token, issuer_pk = step3_exchange_token(client, auth_code)
        
        success = step4_access_resource(
            access_token,
            client_eph_pk,
            client_eph_sk,
            f"{args.resource_server}/api/userinfo"
        )
        
        step5_display_results(success)
        
        print("\n" + "=" * 60)
        print("\n📝 Note: This is a demonstration with simulated network calls.")
        print("   For real deployment, start auth and resource servers separately.")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Demo stopped")
        sys.exit(0)
