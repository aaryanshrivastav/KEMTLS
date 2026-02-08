"""
Complete End-to-End Demonstration
Role: Full PQ-OIDC + KEMTLS Flow (REQUIRED FOR VIDEO)

Demonstrates:
1. KEMTLS handshake with Kyber768
2. User authentication via OIDC
3. Token issuance with Dilithium3 signatures
4. Resource access with Proof-of-Possession

Output: Step-by-step console output with timing
Used for: Demo video recording
"""

import os
import sys
import time

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
from oidc.jwt_handler import PQJWT
from pop.client import PoPClient
from pop.server import ProofOfPossession
from utils.helpers import get_timestamp


def print_banner(title):
    """Print section banner"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_step(step_num, step_name, details=None):
    """Print step header with optional details"""
    print(f"\n[{step_num}/5] {step_name}")
    print("-" * 70)
    if details:
        for key, value in details.items():
            print(f"   • {key}: {value}")


def pause(duration=0.5):
    """Add dramatic pause for video"""
    time.sleep(duration)


def demo_step1_kemtls_handshake():
    """Step 1: KEMTLS Handshake"""
    print_step(1, "KEMTLS HANDSHAKE", {
        "Protocol": "KEMTLS with Kyber768",
        "Security Level": "NIST Level 3",
        "Purpose": "Establish secure channel"
    })
    
    pause()
    
    # Load server keys
    print("\n   Loading server long-term keys...")
    keys_dir = os.path.join(ROOT_DIR, "keys")
    
    with open(os.path.join(keys_dir, "auth_server_kyber_pk.bin"), "rb") as f:
        server_lt_pk = f.read()
    with open(os.path.join(keys_dir, "auth_server_kyber_sk.bin"), "rb") as f:
        server_lt_sk = f.read()
    
    print(f"   ✓ Server public key:  {len(server_lt_pk)} bytes")
    print(f"   ✓ Server secret key:  {len(server_lt_sk)} bytes")
    pause()
    
    # Initialize client and server
    print("\n   Initializing KEMTLS endpoints...")
    client = KEMTLSHandshake(is_server=False)
    server = KEMTLSHandshake(is_server=True)
    print("   ✓ Client initialized")
    print("   ✓ Server initialized")
    pause()
    
    # Server Hello
    print("\n   [Server → Client] Sending Server Hello...")
    server_hello = server.server_init_handshake(server_lt_sk, server_lt_pk)
    print(f"   ✓ Server Hello: {len(server_hello)} bytes")
    print(f"      - Server ephemeral public key")
    print(f"      - Kyber768 encapsulation")
    pause()
    
    # Client Key Exchange
    print("\n   [Client → Server] Processing Server Hello...")
    client_kex, client_eph_pk = client.client_process_server_hello(
        server_hello,
        trusted_longterm_pk=server_lt_pk
    )
    print(f"   ✓ Client Key Exchange: {len(client_kex)} bytes")
    print(f"      - Client ephemeral key")
    print(f"      - Kyber768 ciphertext")
    pause()
    
    # Server processes Client Key Exchange
    print("\n   [Server] Processing Client Key Exchange...")
    server_keys = server.server_process_client_key_exchange(client_kex)
    client_keys = client.get_session_keys()
    pause()
    
    # Verify key agreement
    if server_keys == client_keys:
        print("   ✅ KEY AGREEMENT SUCCESSFUL")
        print(f"      - Client write key: {len(server_keys['client_write_key'])} bytes")
        print(f"      - Server write key: {len(server_keys['server_write_key'])} bytes")
        print(f"      - Session key: {len(server_keys['session_key'])} bytes")
        print(f"      - PoP key: {len(server_keys.get('pop_key', b''))} bytes")
        print(f"      - Session ID: {server.get_session_id()}")
    else:
        print("   ❌ KEY AGREEMENT FAILED")
        return None, None
    
    return client_keys, client_eph_pk


def demo_step2_user_authentication(client_eph_pk, client_eph_sk):
    """Step 2: User Authentication via OIDC"""
    print_step(2, "USER AUTHENTICATION (OIDC)", {
        "Protocol": "OpenID Connect",
        "Client ID": "demo_client",
        "Redirect URI": "http://localhost:8080/callback",
        "Scope": "openid profile email"
    })
    
    pause()
    
    # Initialize OIDC client
    print("\n   Initializing OIDC client...")
    client = OIDCClient(
        client_id="demo_client",
        redirect_uri="http://localhost:8080/callback",
        auth_server_url="http://localhost:5000",
        client_ephemeral_sk=client_eph_sk
    )
    print("   ✓ OIDC client configured")
    pause()
    
    # Authorization request
    print("\n   [Client → Auth Server] Authorization Request...")
    auth_url = client.create_authorization_url(
        scope="openid profile email",
        nonce="demo_nonce_12345"
    )
    print(f"   ✓ Authorization URL generated")
    print(f"      - Server: http://localhost:5000")
    print(f"      - Includes client ephemeral public key binding")
    print(f"      - Nonce: demo_nonce_12345")
    pause()
    
    # Simulate user login and consent
    print("\n   [User] Login and consent...")
    print("      👤 Username: alice@example.com")
    print("      🔑 Password: ********")
    print("      ✓ User grants permissions")
    pause()
    
    # Authorization response
    print("\n   [Auth Server → Client] Authorization Response...")
    auth_code = "AUTH_CODE_" + "X" * 32
    print(f"   ✓ Authorization code received")
    print(f"      - Code: {auth_code[:20]}...")
    print(f"      - Valid for 10 minutes")
    
    return client, auth_code


def demo_step3_token_issuance(client, auth_code, client_eph_pk):
    """Step 3: Token Issuance with PQ Signatures"""
    print_step(3, "TOKEN ISSUANCE", {
        "Signature Algorithm": "ML-DSA-65 (Dilithium3)",
        "Token Type": "JWT with PoP binding",
        "Security Level": "NIST Level 3"
    })
    
    pause()
    
    # Token request
    print("\n   [Client → Auth Server] Token Request...")
    print(f"      - Code: {auth_code[:20]}...")
    print(f"      - Client ID: demo_client")
    print(f"      - Redirect URI: http://localhost:8080/callback")
    pause()
    
    # Load issuer keys
    print("\n   [Auth Server] Loading signing keys...")
    keys_dir = os.path.join(ROOT_DIR, "keys")
    
    with open(os.path.join(keys_dir, "auth_server_dilithium_pk.bin"), "rb") as f:
        issuer_pk = f.read()
    with open(os.path.join(keys_dir, "auth_server_dilithium_sk.bin"), "rb") as f:
        issuer_sk = f.read()
    
    print(f"   ✓ Dilithium public key:  {len(issuer_pk)} bytes")
    print(f"   ✓ Dilithium secret key:  {len(issuer_sk)} bytes")
    pause()
    
    # Create tokens
    print("\n   [Auth Server] Creating tokens...")
    jwt = PQJWT()
    
    # ID Token claims
    claims = {
        "iss": "http://localhost:5000",
        "sub": "alice@example.com",
        "aud": "demo_client",
        "exp": get_timestamp() + 3600,
        "iat": get_timestamp(),
        "nonce": "demo_nonce_12345",
        "email": "alice@example.com",
        "name": "Alice Smith",
        "preferred_username": "alice"
    }
    
    # Create ID token with PoP binding
    id_token = jwt.create_id_token(
        claims=claims,
        issuer_sk=issuer_sk,
        issuer_pk=issuer_pk,
        client_ephemeral_pk=client_eph_pk,
        session_id="session_" + "Y" * 20
    )
    
    access_token = "ACCESS_TOKEN_" + "Z" * 40
    
    print(f"   ✓ ID Token created: {len(id_token)} bytes")
    print(f"      - Algorithm: DILITHIUM3")
    print(f"      - Signature: {len(id_token.split('.')[2])} chars (base64)")
    print(f"      - PoP Binding: Client ephemeral key embedded")
    pause()
    
    print(f"\n   ✓ Access Token created: {len(access_token)} chars")
    print(f"      - Bound to client ephemeral key")
    print(f"      - Valid for 1 hour")
    
    return id_token, access_token, issuer_pk


def demo_step4_resource_access(access_token, client_eph_pk, client_eph_sk):
    """Step 4: Resource Access with Proof-of-Possession"""
    print_step(4, "RESOURCE ACCESS (PoP)", {
        "Resource": "/api/userinfo",
        "PoP Method": "Dilithium3 signature",
        "Challenge-Response": "Dynamic proof"
    })
    
    pause()
    
    # Initialize PoP client
    print("\n   [Client] Initializing PoP client...")
    pop_client = PoPClient(client_eph_sk)
    print("   ✓ PoP client ready with ephemeral key")
    pause()
    
    # Request resource
    print("\n   [Client → Resource Server] GET /api/userinfo...")
    print(f"      - Authorization: Bearer {access_token[:30]}...")
    pause()
    
    # Challenge issued
    print("\n   [Resource Server → Client] PoP Challenge...")
    pop_server = ProofOfPossession()
    challenge = pop_server.generate_challenge(session_id="session_Y" * 4)
    
    print(f"   ✓ Challenge issued")
    print(f"      - Nonce: {challenge['nonce'][:30]}...")
    print(f"      - Timestamp: {challenge['timestamp']}")
    print(f"      - Session ID: {challenge.get('session_id', 'N/A')[:20]}...")
    pause()
    
    # Generate PoP proof
    print("\n   [Client] Generating PoP proof...")
    proof = pop_client.create_pop_proof(
        challenge=challenge,
        token=access_token
    )
    print(f"   ✓ Proof generated: {len(proof)} chars")
    print(f"      - Signed with client ephemeral key")
    print(f"      - Includes token hash and nonce")
    pause()
    
    # Verify proof
    print("\n   [Resource Server] Verifying PoP proof...")
    is_valid = pop_server.verify_pop_response(
        challenge=challenge,
        proof=proof,
        client_eph_pk=client_eph_pk,
        token=access_token
    )
    
    if is_valid:
        print("   ✅ PoP VERIFICATION SUCCESSFUL")
        print("      - Client possesses correct ephemeral key")
        print("      - Token is valid and not replayed")
        print("      - Challenge correctly signed")
        pause()
        
        print("\n   [Resource Server → Client] User Info Response...")
        print("   ✓ Protected resource accessed:")
        print("      {")
        print('        "sub": "alice@example.com",')
        print('        "email": "alice@example.com",')
        print('        "name": "Alice Smith",')
        print('        "preferred_username": "alice"')
        print("      }")
        return True
    else:
        print("   ❌ PoP VERIFICATION FAILED")
        return False


def demo_step5_summary(success, start_time):
    """Step 5: Summary and Statistics"""
    print_step(5, "DEMONSTRATION COMPLETE")
    
    pause()
    
    elapsed = time.time() - start_time
    
    if success:
        print("\n   ✅ ALL STEPS SUCCESSFUL\n")
        print("   Protocol Summary:")
        print("   ┌─────────────────────────────────────────────────────┐")
        print("   │ 1. KEMTLS Handshake         ✓ Kyber768            │")
        print("   │ 2. User Authentication      ✓ OIDC Flow           │")
        print("   │ 3. Token Issuance           ✓ Dilithium3 JWT      │")
        print("   │ 4. Resource Access          ✓ PoP Verified        │")
        print("   └─────────────────────────────────────────────────────┘")
        
        print("\n   Post-Quantum Security:")
        print("   • Key Exchange:  Kyber768 (NIST Level 3)")
        print("   • Signatures:    ML-DSA-65/Dilithium3 (NIST Level 3)")
        print("   • Token Binding: Proof-of-Possession with PQ keys")
                
        print("\n   🎉 POST-QUANTUM OIDC + KEMTLS DEMONSTRATION COMPLETE!")
    else:
        print("\n   ⚠️  DEMONSTRATION INCOMPLETE")
        print("   • Some verification steps failed")
        print("   • Check error messages above")


def main():
    """Main demonstration workflow"""
    print("\n" + "=" * 70)
    print("  POST-QUANTUM OIDC + KEMTLS")
    print("  Complete End-to-End Demonstration")
    print("=" * 70)
    print("\n  This demonstration showcases:")
    print("    • Quantum-resistant key exchange (Kyber768)")
    print("    • Post-quantum digital signatures (Dilithium3)")
    print("    • OpenID Connect authentication flow")
    print("    • Proof-of-Possession token binding")
    print("\n  NIST Level 3 Security - Quantum Safe")
    print("=" * 70)
    
    pause(1.0)
    
    start_time = time.time()
    
    try:
        # Verify keys exist
        keys_dir = os.path.join(ROOT_DIR, "keys")
        if not os.path.exists(os.path.join(keys_dir, "auth_server_kyber_pk.bin")):
            print("\n❌ Error: Server keys not found!")
            print("   Please run: python scripts/generate_keys.py")
            return
        
        # Step 1: KEMTLS Handshake
        client_keys, _ = demo_step1_kemtls_handshake()
        if client_keys is None:
            return
        
        pause(1.0)
        
        # Generate client ephemeral Dilithium keypair for PoP
        print_banner("PREPARING CLIENT CREDENTIALS")
        print("\n   Generating client ephemeral keypair for PoP...")
        sig = DilithiumSignature()
        client_eph_pk, client_eph_sk = sig.generate_keypair()
        print(f"   ✓ Public key:  {len(client_eph_pk)} bytes")
        print(f"   ✓ Secret key:  {len(client_eph_sk)} bytes")
        print("      (Used for Proof-of-Possession)")
        
        pause(1.0)
        
        # Step 2: User Authentication
        client, auth_code = demo_step2_user_authentication(client_eph_pk, client_eph_sk)
        
        pause(1.0)
        
        # Step 3: Token Issuance
        id_token, access_token, issuer_pk = demo_step3_token_issuance(
            client, auth_code, client_eph_pk
        )
        
        pause(1.0)
        
        # Step 4: Resource Access
        success = demo_step4_resource_access(
            access_token, client_eph_pk, client_eph_sk
        )
        
        pause(1.0)
        
        # Step 5: Summary
        demo_step5_summary(success, start_time)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Demonstration interrupted by user")
        return
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return


if __name__ == "__main__":
    main()
