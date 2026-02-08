"""Virtual sandbox test for crypto package.

Runs crypto modules with dummy replacements for external dependencies.
Prints each function execution to CLI.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types


CURRENT_DIR = os.path.dirname(__file__)
SRC_DIR = os.path.dirname(CURRENT_DIR)

# Avoid stdlib `token` shadowing when running as a script from src/crypto
if sys.path and sys.path[0] == CURRENT_DIR:
    sys.path.pop(0)

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


def _load_module(module_name: str, file_path: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module: {module_name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _install_fake_dependencies() -> None:
    # cryptography stubs for aead and kdf
    cryptography_pkg = types.ModuleType("cryptography")
    cryptography_pkg.__path__ = []
    sys.modules["cryptography"] = cryptography_pkg

    # exceptions
    exceptions_mod = types.ModuleType("cryptography.exceptions")

    class InvalidTag(Exception):
        pass

    exceptions_mod.InvalidTag = InvalidTag
    sys.modules["cryptography.exceptions"] = exceptions_mod

    # hazmat.primitives.ciphers.aead
    hazmat_pkg = types.ModuleType("cryptography.hazmat")
    hazmat_primitives = types.ModuleType("cryptography.hazmat.primitives")
    hazmat_ciphers = types.ModuleType("cryptography.hazmat.primitives.ciphers")
    hazmat_ciphers_aead = types.ModuleType(
        "cryptography.hazmat.primitives.ciphers.aead"
    )

    class ChaCha20Poly1305:
        def __init__(self, key: bytes):
            self.key = key

        def encrypt(self, nonce: bytes, plaintext: bytes, associated_data: bytes | None):
            return plaintext + (b"T" * 16)

        def decrypt(self, nonce: bytes, ciphertext_with_tag: bytes, associated_data: bytes | None):
            if len(ciphertext_with_tag) < 16:
                raise InvalidTag()
            return ciphertext_with_tag[:-16]

    hazmat_ciphers_aead.ChaCha20Poly1305 = ChaCha20Poly1305

    sys.modules["cryptography.hazmat"] = hazmat_pkg
    sys.modules["cryptography.hazmat.primitives"] = hazmat_primitives
    sys.modules["cryptography.hazmat.primitives.ciphers"] = hazmat_ciphers
    sys.modules["cryptography.hazmat.primitives.ciphers.aead"] = hazmat_ciphers_aead

    # hazmat.primitives.hashes
    hazmat_hashes = types.ModuleType("cryptography.hazmat.primitives.hashes")

    class _SHA256:
        name = "SHA256"

    hazmat_hashes.SHA256 = lambda: _SHA256()
    sys.modules["cryptography.hazmat.primitives.hashes"] = hazmat_hashes

    # hazmat.primitives.kdf.hkdf
    hazmat_kdf = types.ModuleType("cryptography.hazmat.primitives.kdf")
    hazmat_kdf_hkdf = types.ModuleType("cryptography.hazmat.primitives.kdf.hkdf")

    class HKDF:
        def __init__(self, algorithm, length: int, salt: bytes | None, info: bytes):
            self.length = length
            self.info = info

        def derive(self, master_secret: bytes) -> bytes:
            return (master_secret + self.info)[: self.length].ljust(self.length, b"\x00")

    hazmat_kdf_hkdf.HKDF = HKDF
    sys.modules["cryptography.hazmat.primitives.kdf"] = hazmat_kdf
    sys.modules["cryptography.hazmat.primitives.kdf.hkdf"] = hazmat_kdf_hkdf

    # oqs stubs for kyber and dilithium
    oqs_mod = types.ModuleType("oqs")

    class Signature:
        def __init__(self, alg, secret_key: bytes | None = None):
            self.alg = alg
            self.secret_key = secret_key

        def generate_keypair(self):
            return b"pk" * 652

        def export_secret_key(self):
            return b"sk" * 1334

        def sign(self, message: bytes):
            return b"sig" * 1097

        def verify(self, message: bytes, signature: bytes, public_key: bytes):
            return True

    class KeyEncapsulation:
        def __init__(self, alg, secret_key: bytes | None = None):
            self.alg = alg
            self.secret_key = secret_key

        def generate_keypair(self):
            return b"pk" * 592

        def export_secret_key(self):
            return b"sk" * 800

        def encap_secret(self, public_key: bytes):
            return b"ct" * 544, b"ss" * 16

        def decap_secret(self, ciphertext: bytes):
            return b"ss" * 16

    oqs_mod.Signature = Signature
    oqs_mod.KeyEncapsulation = KeyEncapsulation
    sys.modules["oqs"] = oqs_mod


def run_sandbox() -> None:
    print("[sandbox] installing fake dependencies")
    _install_fake_dependencies()

    print("[sandbox] loading crypto modules")
    aead = _load_module("crypto.aead", os.path.join(CURRENT_DIR, "aead.py"))
    kdf = _load_module("crypto.kdf", os.path.join(CURRENT_DIR, "kdf.py"))
    dilithium_sig = _load_module(
        "crypto.dilithium_sig", os.path.join(CURRENT_DIR, "dilithium_sig.py")
    )
    kyber_kem = _load_module(
        "crypto.kyber_kem", os.path.join(CURRENT_DIR, "kyber_kem.py")
    )

    print("[aead] generate_key / encrypt / decrypt")
    key = aead.AEADCipher.generate_key()
    cipher = aead.AEADCipher(key)
    encrypted = cipher.encrypt(b"hello")
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == b"hello"

    print("[kdf] derive_session_keys / derive_single_key")
    keys = kdf.KeyDerivation.derive_session_keys([b"a" * 32, b"b" * 32], b"t" * 32)
    assert "client_write_key" in keys
    single = kdf.KeyDerivation.derive_single_key(b"c" * 32, b"context")
    assert len(single) == 32

    print("[dilithium] generate_keypair / sign / verify")
    sig = dilithium_sig.DilithiumSignature()
    pk, sk = sig.generate_keypair()
    signature = sig.sign(sk, b"msg")
    assert sig.verify(pk, b"msg", signature) is True

    print("[kyber] generate_keypair / encapsulate / decapsulate")
    kem = kyber_kem.KyberKEM()
    kem_pk, kem_sk = kem.generate_keypair()
    ct, ss = kem.encapsulate(kem_pk)
    ss2 = kem.decapsulate(kem_sk, ct)
    assert ss2 == ss

    print("✅ crypto sandbox checks passed")


if __name__ == "__main__":
    run_sandbox()
