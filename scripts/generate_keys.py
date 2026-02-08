"""
Generate All Server Keys
Role: Generate all server keys for Auth Server

Generates:
- Auth server Kyber keypair (KEMTLS)
- Auth server Dilithium keypair (JWT signing)
Saves to keys/ directory
"""

import os
import sys

# Add src to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from crypto.kyber_kem import KyberKEM
from crypto.dilithium_sig import DilithiumSignature


def ensure_keys_directory():
    """Ensure keys/ directory exists"""
    keys_dir = os.path.join(ROOT_DIR, "keys")
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir)
        print(f"✓ Created keys/ directory: {keys_dir}")
    return keys_dir


def generate_kyber_keys(keys_dir):
    """Generate Auth server Kyber768 keypair for KEMTLS"""
    print("\n1. Generating Kyber768 keypair for KEMTLS...")
    kem = KyberKEM()
    pk, sk = kem.generate_keypair()
    
    # Save keys
    pk_path = os.path.join(keys_dir, "auth_server_kyber_pk.bin")
    sk_path = os.path.join(keys_dir, "auth_server_kyber_sk.bin")
    
    with open(pk_path, "wb") as f:
        f.write(pk)
    print(f"   ✓ Public key saved: {pk_path} ({len(pk)} bytes)")
    
    with open(sk_path, "wb") as f:
        f.write(sk)
    print(f"   ✓ Secret key saved: {sk_path} ({len(sk)} bytes)")
    
    return pk, sk


def generate_dilithium_keys(keys_dir):
    """Generate Auth server Dilithium keypair for JWT signing"""
    print("\n2. Generating ML-DSA-65 (Dilithium3) keypair for JWT signing...")
    sig = DilithiumSignature()
    pk, sk = sig.generate_keypair()
    
    # Save keys
    pk_path = os.path.join(keys_dir, "auth_server_dilithium_pk.bin")
    sk_path = os.path.join(keys_dir, "auth_server_dilithium_sk.bin")
    
    with open(pk_path, "wb") as f:
        f.write(pk)
    print(f"   ✓ Public key saved: {pk_path} ({len(pk)} bytes)")
    
    with open(sk_path, "wb") as f:
        f.write(sk)
    print(f"   ✓ Secret key saved: {sk_path} ({len(sk)} bytes)")
    
    return pk, sk


def main():
    """Main key generation workflow"""
    print("=" * 60)
    print("Auth Server Key Generation")
    print("=" * 60)
    
    # Ensure keys directory exists
    keys_dir = ensure_keys_directory()
    
    # Generate Kyber keypair for KEMTLS
    kyber_pk, kyber_sk = generate_kyber_keys(keys_dir)
    
    # Generate Dilithium keypair for JWT signing
    dilithium_pk, dilithium_sk = generate_dilithium_keys(keys_dir)
    
    # Summary
    print("\n" + "=" * 60)
    print("✅ Key Generation Complete")
    print("=" * 60)
    print("\nGenerated keys:")
    print(f"  • Kyber768 (KEMTLS)")
    print(f"    - Public:  auth_server_kyber_pk.bin")
    print(f"    - Secret:  auth_server_kyber_sk.bin")
    print(f"  • ML-DSA-65 (JWT signatures)")
    print(f"    - Public:  auth_server_dilithium_pk.bin")
    print(f"    - Secret:  auth_server_dilithium_sk.bin")
    print(f"\nAll keys saved to: {keys_dir}")
    print("\n⚠️  Keep secret keys secure and never commit to version control!")


if __name__ == "__main__":
    main()
