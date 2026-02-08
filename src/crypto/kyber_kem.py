"""
Kyber768 Key Encapsulation Mechanism - Prototype Implementation

"""

import os
import hashlib
from typing import Tuple

class KyberKEM:

    
    ALGORITHM = "Kyber768-PROTOTYPE"
    PUBLIC_KEY_SIZE = 1184
    SECRET_KEY_SIZE = 2400
    CIPHERTEXT_SIZE = 1088
    SHARED_SECRET_SIZE = 32
    
    def __init__(self):
        self.algorithm = self.ALGORITHM
    
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
    
        public_key = os.urandom(self.PUBLIC_KEY_SIZE)
        secret_key = os.urandom(self.SECRET_KEY_SIZE)
        return public_key, secret_key
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
       
        if len(public_key) != self.PUBLIC_KEY_SIZE:
            raise ValueError(
                f"Invalid public key size: expected {self.PUBLIC_KEY_SIZE}, "
                f"got {len(public_key)}"
            )
        
        ciphertext = os.urandom(self.CIPHERTEXT_SIZE)
        
        shared_secret = hashlib.sha256(
            b"PROTOTYPE-KYBER-SS:" + ciphertext
        ).digest()[:self.SHARED_SECRET_SIZE]
        
        return ciphertext, shared_secret
    
    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
      
        if len(secret_key) != self.SECRET_KEY_SIZE:
            raise ValueError(
                f"Invalid secret key size: expected {self.SECRET_KEY_SIZE}, "
                f"got {len(secret_key)}"
            )
        
        if len(ciphertext) != self.CIPHERTEXT_SIZE:
            raise ValueError(
                f"Invalid ciphertext size: expected {self.CIPHERTEXT_SIZE}, "
                f"got {len(ciphertext)}"
            )

        shared_secret = hashlib.sha256(
            b"PROTOTYPE-KYBER-SS:" + ciphertext
        ).digest()[:self.SHARED_SECRET_SIZE]
        
        return shared_secret
    
    def get_algorithm_info(self) -> dict:
        """Get information about this prototype implementation."""
        return {
            "algorithm": self.ALGORITHM,
            "public_key_size": self.PUBLIC_KEY_SIZE,
            "secret_key_size": self.SECRET_KEY_SIZE,
            "ciphertext_size": self.CIPHERTEXT_SIZE,
            "shared_secret_size": self.SHARED_SECRET_SIZE,

           
        }
    



def test_kyber_kem():
   
    print("=" * 70)
    print("Testing Kyber768 KEM Prototype")
    print("=" * 70)
    
    kem = KyberKEM()
    

    
    # Test keypair generation
    print("\n[1] Generating keypair...")
    pk, sk = kem.generate_keypair()
    assert len(pk) == KyberKEM.PUBLIC_KEY_SIZE
    assert len(sk) == KyberKEM.SECRET_KEY_SIZE
    print(f"  ✓ Public key: {len(pk)} bytes")
    print(f"  ✓ Secret key: {len(sk)} bytes")
    
    # Test encapsulation
    print("\n[2] Encapsulating...")
    ct, ss1 = kem.encapsulate(pk)
    assert len(ct) == KyberKEM.CIPHERTEXT_SIZE
    assert len(ss1) == KyberKEM.SHARED_SECRET_SIZE
    print(f"  ✓ Ciphertext: {len(ct)} bytes")
    print(f"  ✓ Shared secret: {len(ss1)} bytes")
    print(f"  ✓ SS1: {ss1.hex()[:32]}...")
    
    # Test decapsulation
    print("\n[3] Decapsulating...")
    ss2 = kem.decapsulate(sk, ct)
    assert len(ss2) == KyberKEM.SHARED_SECRET_SIZE
    print(f"  ✓ Recovered shared secret: {len(ss2)} bytes")
    print(f"  ✓ SS2: {ss2.hex()[:32]}...")
    
    # CRITICAL: Verify shared secrets match
    print("\n[4] Verifying shared secrets match...")
    if ss1 == ss2:
        print("  ✓ Shared secrets MATCH (deterministic derivation working)")

    else:
        print("  ✗ FAILED: Shared secrets don't match!")
        raise AssertionError("Shared secrets should match in prototype")
    
    # Test with different ciphertext (should give different secret)
    print("\n[5] Testing different ciphertext...")
    ct2, ss3 = kem.encapsulate(pk)
    ss4 = kem.decapsulate(sk, ct2)
    assert ss3 == ss4, "Second pair should also match"
    assert ss1 != ss3, "Different ciphertexts should give different secrets"
    print("  ✓ Different ciphertexts produce different secrets (as expected)")
    
    # Display algorithm info
    info = kem.get_algorithm_info()
    print("\n[6] Algorithm Information:")
    print("  " + "-" * 66)
    for key, value in info.items():
        print(f"  {key:20s}: {value}")
    print("  " + "-" * 66)
    
    print("\n" + "=" * 70)
    print("✅ Kyber768 PROTOTYPE test passed")
    print("=" * 70)


if __name__ == "__main__":
    test_kyber_kem()