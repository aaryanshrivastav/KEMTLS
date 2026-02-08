"""
Post-Quantum Cryptographic Primitives

This module provides wrappers around post-quantum cryptographic algorithms
and symmetric cryptography primitives used in the KEMTLS-based OIDC implementation.

Modules:
    - kyber_kem: Kyber768 Key Encapsulation Mechanism
    - dilithium_sig: Dilithium3 Digital Signatures
    - aead: ChaCha20-Poly1305 Authenticated Encryption
    - kdf: HKDF Key Derivation Function
"""

from .kyber_kem import KyberKEM
from .dilithium_sig import DilithiumSignature
from .aead import AEADCipher
from .kdf import KeyDerivation

__all__ = [
    "KyberKEM",
    "DilithiumSignature",
    "AEADCipher",
    "KeyDerivation",
]
