"""Primitive AEAD helpers for the KEMTLS record layer."""

from __future__ import annotations

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16


def seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Encrypt and authenticate plaintext with ChaCha20-Poly1305."""
    _validate_bytes("key", key, KEY_SIZE)
    _validate_bytes("nonce", nonce, NONCE_SIZE)
    _validate_bytes("plaintext", plaintext)
    _validate_bytes("aad", aad)

    chacha20_poly1305 = _load_chacha20_poly1305()
    return chacha20_poly1305(key).encrypt(nonce, plaintext, aad)


def open_(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypt and authenticate ciphertext with ChaCha20-Poly1305."""
    _validate_bytes("key", key, KEY_SIZE)
    _validate_bytes("nonce", nonce, NONCE_SIZE)
    _validate_bytes("ciphertext", ciphertext)
    _validate_bytes("aad", aad)
    if len(ciphertext) < TAG_SIZE:
        raise ValueError(
            f"ciphertext must be at least {TAG_SIZE} bytes to include an authentication tag"
        )

    try:
        chacha20_poly1305 = _load_chacha20_poly1305()
        return chacha20_poly1305(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise ValueError("authentication tag verification failed") from exc


def xor_iv_with_seq(iv: bytes, seq: int) -> bytes:
    """Derive a deterministic record nonce by XORing the IV with the sequence number."""
    _validate_bytes("iv", iv, NONCE_SIZE)
    if not isinstance(seq, int):
        raise TypeError("seq must be an integer")
    if seq < 0 or seq >= 1 << 64:
        raise ValueError("seq must be between 0 and 2^64 - 1")

    seq_bytes = seq.to_bytes(8, "big")
    padded_seq = b"\x00" * (NONCE_SIZE - len(seq_bytes)) + seq_bytes
    return bytes(left ^ right for left, right in zip(iv, padded_seq))


def _validate_bytes(name: str, value: bytes, expected_length: int | None = None) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if expected_length is not None and len(value) != expected_length:
        raise ValueError(
            f"Invalid {name} size: expected {expected_length} bytes, got {len(value)}"
        )


def _load_chacha20_poly1305():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "cryptography is required for ChaCha20-Poly1305 AEAD operations."
        ) from exc

    return ChaCha20Poly1305


__all__ = ["KEY_SIZE", "NONCE_SIZE", "TAG_SIZE", "open_", "seal", "xor_iv_with_seq"]
