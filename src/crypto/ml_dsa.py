"""ML-DSA-65 wrapper and JWK conversion helpers."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from utils.encoding import base64url_decode, base64url_encode


def _load_ml_dsa_backend():
    try:
        from pqcrypto.sign import ml_dsa_65  # type: ignore
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "pqcrypto with ML-DSA-65 support is required for signature operations."
        ) from exc

    return ml_dsa_65


class MLDSA65:
    """Stateless ML-DSA-65 signing operations."""

    ALGORITHM = "ML-DSA-65"
    JWK_KEY_TYPE = "AKP"
    PUBLIC_KEY_SIZE = 1952
    SECRET_KEY_SIZE = 4032
    SIGNATURE_SIZE = 3309

    @classmethod
    def generate_keypair(cls) -> Tuple[bytes, bytes]:
        """Generate a fresh ML-DSA-65 keypair."""
        backend = _load_ml_dsa_backend()
        public_key, secret_key = backend.generate_keypair()
        cls._validate_public_key(public_key)
        cls._validate_secret_key(secret_key)
        return public_key, secret_key

    @classmethod
    def sign(cls, secret_key: bytes, message: bytes) -> bytes:
        """Sign a message with ML-DSA-65."""
        cls._validate_secret_key(secret_key)
        cls._validate_message(message)

        backend = _load_ml_dsa_backend()
        signature = backend.sign(secret_key, message)
        cls._validate_signature(signature)
        return signature

    @classmethod
    def verify(cls, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify an ML-DSA-65 signature."""
        cls._validate_public_key(public_key)
        cls._validate_message(message)
        cls._validate_signature(signature)

        backend = _load_ml_dsa_backend()
        try:
            return bool(backend.verify(public_key, message, signature))
        except Exception:
            return False

    @classmethod
    def public_key_to_jwk(cls, public_key: bytes, kid: Optional[str] = None) -> Dict[str, str]:
        """Encode an ML-DSA-65 public key as a minimal JWK."""
        cls._validate_public_key(public_key)
        if kid is not None and not isinstance(kid, str):
            raise TypeError("kid must be a string when provided")

        jwk = {
            "kty": cls.JWK_KEY_TYPE,
            "alg": cls.ALGORITHM,
            "use": "sig",
            "x": base64url_encode(public_key),
        }
        if kid:
            jwk["kid"] = kid
        return jwk

    @classmethod
    def jwk_to_public_key(cls, jwk: Dict[str, Any]) -> bytes:
        """Decode and validate an ML-DSA-65 JWK."""
        if not isinstance(jwk, dict):
            raise TypeError("jwk must be a dictionary")

        if jwk.get("kty") != cls.JWK_KEY_TYPE:
            raise ValueError(
                f"Invalid JWK key type: expected {cls.JWK_KEY_TYPE}, got {jwk.get('kty')}"
            )
        if jwk.get("alg") != cls.ALGORITHM:
            raise ValueError(
                f"Invalid JWK algorithm: expected {cls.ALGORITHM}, got {jwk.get('alg')}"
            )
        if "x" not in jwk:
            raise ValueError("JWK missing required 'x' public key field")
        if "use" in jwk and jwk["use"] != "sig":
            raise ValueError("JWK 'use' must be 'sig' for ML-DSA verification keys")

        public_key = base64url_decode(jwk["x"])
        cls._validate_public_key(public_key)
        return public_key

    @classmethod
    def _validate_message(cls, message: bytes) -> None:
        if not isinstance(message, bytes):
            raise TypeError("message must be bytes")

    @classmethod
    def _validate_public_key(cls, public_key: bytes) -> None:
        cls._validate_bytes("public_key", public_key, cls.PUBLIC_KEY_SIZE)

    @classmethod
    def _validate_secret_key(cls, secret_key: bytes) -> None:
        cls._validate_bytes("secret_key", secret_key, cls.SECRET_KEY_SIZE)

    @classmethod
    def _validate_signature(cls, signature: bytes) -> None:
        cls._validate_bytes("signature", signature, cls.SIGNATURE_SIZE)

    @staticmethod
    def _validate_bytes(name: str, value: bytes, expected_length: int) -> None:
        if not isinstance(value, bytes):
            raise TypeError(f"{name} must be bytes")
        if len(value) != expected_length:
            raise ValueError(
                f"Invalid {name} size: expected {expected_length} bytes, got {len(value)}"
            )


__all__ = ["MLDSA65"]
