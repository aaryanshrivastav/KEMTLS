"""Role: Unit tests for cryptographic primitives.

Tests:
- Kyber encap/decap correctness
- Dilithium sign/verify correctness
- AEAD encrypt/decrypt
- Key derivation

Ensures: Crypto operations work correctly
"""

import os
import sys
import unittest


ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


from crypto.kyber_kem import KyberKEM
from crypto.dilithium_sig import DilithiumSignature
from crypto.aead import AEADCipher
from crypto.kdf import KeyDerivation


class TestKyberKEM(unittest.TestCase):
    def test_encap_decap_correctness(self):
        kem = KyberKEM()
        pk, sk = kem.generate_keypair()
        ct, ss1 = kem.encapsulate(pk)
        ss2 = kem.decapsulate(sk, ct)
        self.assertEqual(ss1, ss2)


class TestDilithiumSignature(unittest.TestCase):
    def test_sign_verify_correctness(self):
        sig = DilithiumSignature()
        pk, sk = sig.generate_keypair()
        message = b"test-message"
        signature = sig.sign(sk, message)
        self.assertTrue(sig.verify(pk, message, signature))
        self.assertFalse(sig.verify(pk, b"tampered", signature))


class TestAEAD(unittest.TestCase):
    def test_encrypt_decrypt(self):
        key = AEADCipher.generate_key()
        cipher = AEADCipher(key)
        plaintext = b"secret"
        aad = b"aad"
        encrypted = cipher.encrypt(plaintext, aad)
        decrypted = cipher.decrypt(encrypted, aad)
        self.assertEqual(decrypted, plaintext)


class TestKeyDerivation(unittest.TestCase):
    def test_derive_session_keys(self):
        ss1 = b"a" * 32
        ss2 = b"b" * 32
        transcript = b"t" * 32
        keys = KeyDerivation.derive_session_keys([ss1, ss2], transcript)
        self.assertEqual(len(keys["client_write_key"]), 32)
        self.assertEqual(len(keys["server_write_key"]), 32)
        self.assertEqual(len(keys["session_key"]), 32)
        self.assertEqual(len(keys["pop_key"]), 32)

    def test_derive_single_key(self):
        ss = b"c" * 32
        key = KeyDerivation.derive_single_key(ss, b"context")
        self.assertEqual(len(key), 32)


if __name__ == "__main__":
    unittest.main()
