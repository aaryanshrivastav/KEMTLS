"""ML-KEM-768 wrapper built on liboqs-python."""

from __future__ import annotations

from typing import Tuple


def _load_oqs():
    try:
        import oqs  # type: ignore
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "liboqs-python is required for ML-KEM-768 operations. "
            "Install the 'oqs' package and liboqs runtime before using this module."
        ) from exc

    return oqs


class MLKEM768:
    """Stateless ML-KEM-768 operations with strict input validation."""

    ALGORITHM = "ML-KEM-768"
    PUBLIC_KEY_SIZE = 1184
    SECRET_KEY_SIZE = 2400
    CIPHERTEXT_SIZE = 1088
    SHARED_SECRET_SIZE = 32

    @classmethod
    def generate_keypair(cls) -> Tuple[bytes, bytes]:
        """Generate a fresh ML-KEM-768 keypair."""
        oqs = _load_oqs()
        with oqs.KeyEncapsulation(cls.ALGORITHM) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()

        cls._validate_public_key(public_key)
        cls._validate_secret_key(secret_key)
        return public_key, secret_key

    @classmethod
    def encapsulate(cls, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate to an ML-KEM-768 public key."""
        cls._validate_public_key(public_key)

        oqs = _load_oqs()
        with oqs.KeyEncapsulation(cls.ALGORITHM) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)

        cls._validate_ciphertext(ciphertext)
        cls._validate_shared_secret(shared_secret)
        return ciphertext, shared_secret

    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate an ML-KEM-768 ciphertext."""
        cls._validate_secret_key(secret_key)
        cls._validate_ciphertext(ciphertext)

        oqs = _load_oqs()
        with oqs.KeyEncapsulation(cls.ALGORITHM, secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)

        cls._validate_shared_secret(shared_secret)
        return shared_secret

    @classmethod
    def _validate_public_key(cls, public_key: bytes) -> None:
        cls._validate_bytes("public_key", public_key, cls.PUBLIC_KEY_SIZE)

    @classmethod
    def _validate_secret_key(cls, secret_key: bytes) -> None:
        cls._validate_bytes("secret_key", secret_key, cls.SECRET_KEY_SIZE)

    @classmethod
    def _validate_ciphertext(cls, ciphertext: bytes) -> None:
        cls._validate_bytes("ciphertext", ciphertext, cls.CIPHERTEXT_SIZE)

    @classmethod
    def _validate_shared_secret(cls, shared_secret: bytes) -> None:
        cls._validate_bytes("shared_secret", shared_secret, cls.SHARED_SECRET_SIZE)

    @staticmethod
    def _validate_bytes(name: str, value: bytes, expected_length: int) -> None:
        if not isinstance(value, bytes):
            raise TypeError(f"{name} must be bytes")
        if len(value) != expected_length:
            raise ValueError(
                f"Invalid {name} size: expected {expected_length} bytes, got {len(value)}"
            )


__all__ = ["MLKEM768"]
