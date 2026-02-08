"""
ML-DSA-65 (Dilithium3 equivalent) Digital Signature
"""

from pqcrypto.sign import ml_dsa_65  # NIST Level 3 Dilithium3
from typing import Tuple


class DilithiumSignature:
    """
    ML-DSA-65 Digital Signature Scheme (Dilithium3 equivalent)
    
    NIST Level 3 post-quantum signatures via pqcrypto.ml_dsa_65
    """
    
    ALGORITHM = "ML-DSA-65 (Dilithium3)"
    PUBLIC_KEY_SIZE = 1952
    SECRET_KEY_SIZE = 4032
    SIGNATURE_SIZE = 3309
    
    def __init__(self):
        self.algorithm = self.ALGORITHM
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new ML-DSA-65 keypair (Dilithium3 sizes).
        """
        pk, sk = ml_dsa_65.generate_keypair()
        return pk, sk
    
    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """
        Sign a message using ML-DSA-65.
        """
        if not isinstance(message, bytes):
            raise TypeError("Message must be bytes")
        signature = ml_dsa_65.sign(secret_key, message)
        return signature
    
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify a ML-DSA-65 signature.
        """
        if not isinstance(message, bytes):
            raise TypeError("Message must be bytes")
        try:
            # ml_dsa_65.verify() returns bool (True=valid, False=invalid)
            return ml_dsa_65.verify(public_key, message, signature)
        except Exception:
            return False
    
    def get_algorithm_info(self) -> dict:
        """
        Get information about the ML-DSA-65 algorithm.
        """
        return {
            "algorithm": self.ALGORITHM,
            "backend": "pqcrypto.ml_dsa_65 (REAL NIST Level 3 PQ sigs)",
            "security_level": "NIST Level 3",
            "public_key_size": self.PUBLIC_KEY_SIZE,
            "secret_key_size": self.SECRET_KEY_SIZE,
            "signature_size": self.SIGNATURE_SIZE,
            "type": "Digital Signature",
            "hardness_assumption": "Module-LWE + Fiat-Shamir",
        }


def test_dilithium_signature():
    """
    Test the ML-DSA-65 signature implementation.
    """
    print("Testing ML-DSA-65 (Dilithium3) Signatures...")
    
    sig = DilithiumSignature()
    
    # Test keypair generation
    print("  Generating keypair...")
    pk, sk = sig.generate_keypair()
    print(f"  ✓ Public key: {len(pk)} bytes ✓")
    print(f"  ✓ Secret key: {len(sk)} bytes ✓")
    
    # Test signing
    print("  Signing message...")
    message = b"This is a test message for ML-DSA-65 (Dilithium3) signature"
    signature = sig.sign(sk, message)
    print(f"  ✓ Signature: {len(signature)} bytes ✓")
    
    # Test valid verification
    print("  Verifying valid signature...")
    is_valid = sig.verify(pk, message, signature)
    assert is_valid, "Valid signature should verify!"
    print("  ✓ Valid signature verified ✓✓✓")
    
    # Test tampered message detection
    print("  Testing tampered message detection...")
    tampered = b"This is a TAMPERED message for ML-DSA-65 (Dilithium3)"
    is_valid = sig.verify(pk, tampered, signature)
    assert not is_valid, "Tampered signature should NOT verify!"
    print("  ✓ Tampered message correctly rejected ✓✓✓")
    
    # Test invalid signature
    print("  Testing with invalid signature...")
    invalid_sig = b"\x00" * len(signature)
    is_valid = sig.verify(pk, message, invalid_sig)
    assert not is_valid, "Invalid signature should NOT verify!"
    print(f"  ✓ Invalid signature correctly rejected ✓✓✓")
    
    # Display algorithm info
    info = sig.get_algorithm_info()
    print("\n  Algorithm Information:")
    for key, value in info.items():
        print(f"    {key}: {value}")
    
    print("\n✅ ML-DSA-65 signature test PASSED")


if __name__ == "__main__":
    test_dilithium_signature()