"""Explicit KEMTLS handshake key schedule."""

from __future__ import annotations

import hashlib
import hmac
from typing import Dict, Sequence

from rust_ext import key_schedule as rust_key_schedule


HASH_NAME = "sha256"
HASH_LEN = hashlib.new(HASH_NAME).digest_size
LABEL_PREFIX = b"kemtls13 "


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract using SHA-256."""
    _validate_bytes("salt", salt)
    _validate_bytes("ikm", ikm)
    return rust_key_schedule.hkdf_extract(salt, ikm, fallback=_hkdf_extract_python)


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """HKDF-Expand-Label style derivation with a KEMTLS label prefix."""
    _validate_bytes("secret", secret)
    _validate_bytes("label", label)
    _validate_bytes("context", context)
    if not isinstance(length, int):
        raise TypeError("length must be an integer")
    if length <= 0:
        raise ValueError("length must be positive")

    full_label = LABEL_PREFIX + label
    hkdf_label = (
        length.to_bytes(2, "big")
        + bytes([len(full_label)])
        + full_label
        + bytes([len(context)])
        + context
    )
    return _hkdf_expand(secret, hkdf_label, length)


def compute_transcript_hash(messages: Sequence[bytes]) -> bytes:
    """Hash an ordered transcript of canonical handshake messages."""
    if not isinstance(messages, Sequence):
        raise TypeError("messages must be a sequence of bytes values")
    chunks = []
    for index, message in enumerate(messages):
        if not isinstance(message, bytes):
            raise TypeError(f"transcript message {index} must be bytes")
        chunks.append(message)
    return rust_key_schedule.transcript_hash_many(
        chunks,
        fallback=_transcript_hash_many_python,
    )


def derive_handshake_secret(shared_secrets: Sequence[bytes]) -> bytes:
    """Derive the handshake secret from the ordered KEM shared secrets."""
    if not isinstance(shared_secrets, Sequence):
        raise TypeError("shared_secrets must be a sequence of bytes values")
    if not shared_secrets:
        raise ValueError("shared_secrets must not be empty")

    concatenated = bytearray()
    for index, shared_secret in enumerate(shared_secrets):
        _validate_bytes(f"shared_secret[{index}]", shared_secret, HASH_LEN)
        concatenated.extend(shared_secret)

    return hkdf_extract(b"\x00" * HASH_LEN, bytes(concatenated))


def derive_handshake_traffic_secrets(handshake_secret: bytes, transcript_hash_1: bytes) -> Dict[str, bytes]:
    """Derive client/server handshake traffic secrets from transcript_1."""
    _validate_bytes("handshake_secret", handshake_secret, HASH_LEN)
    _validate_bytes("transcript_hash_1", transcript_hash_1, HASH_LEN)

    return {
        "client_handshake_traffic_secret": hkdf_expand_label(
            handshake_secret, b"c hs traffic", transcript_hash_1, HASH_LEN
        ),
        "server_handshake_traffic_secret": hkdf_expand_label(
            handshake_secret, b"s hs traffic", transcript_hash_1, HASH_LEN
        ),
    }


def derive_finished_keys(client_hs_secret: bytes, server_hs_secret: bytes) -> Dict[str, bytes]:
    """Derive Finished MAC keys from the handshake traffic secrets."""
    _validate_bytes("client_hs_secret", client_hs_secret, HASH_LEN)
    _validate_bytes("server_hs_secret", server_hs_secret, HASH_LEN)

    return {
        "client_finished_key": hkdf_expand_label(
            client_hs_secret, b"finished", b"", HASH_LEN
        ),
        "server_finished_key": hkdf_expand_label(
            server_hs_secret, b"finished", b"", HASH_LEN
        ),
    }


def derive_application_traffic_secrets(handshake_secret: bytes, transcript_hash_3: bytes) -> Dict[str, bytes]:
    """Derive client/server application traffic secrets only after transcript_3."""
    _validate_bytes("handshake_secret", handshake_secret, HASH_LEN)
    _validate_bytes("transcript_hash_3", transcript_hash_3, HASH_LEN)

    derived_secret = hkdf_expand_label(handshake_secret, b"derived", b"", HASH_LEN)
    master_secret = hkdf_extract(b"\x00" * HASH_LEN, derived_secret)

    return {
        "client_application_traffic_secret": hkdf_expand_label(
            master_secret, b"c ap traffic", transcript_hash_3, HASH_LEN
        ),
        "server_application_traffic_secret": hkdf_expand_label(
            master_secret, b"s ap traffic", transcript_hash_3, HASH_LEN
        ),
    }


def _validate_bytes(name: str, value: bytes, expected_length: int | None = None) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if expected_length is not None and len(value) != expected_length:
        raise ValueError(
            f"Invalid {name} size: expected {expected_length} bytes, got {len(value)}"
        )


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length > 255 * HASH_LEN:
        raise ValueError("length exceeds HKDF expand limit")

    return rust_key_schedule.hkdf_expand(prk, info, length, fallback=_hkdf_expand_python)


def _hkdf_extract_python(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, HASH_NAME).digest()


def _transcript_hash_python(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _transcript_hash_many_python(messages: list[bytes]) -> bytes:
    hasher = hashlib.sha256()
    for message in messages:
        hasher.update(message)
    return hasher.digest()


def _hkdf_expand_python(prk: bytes, info: bytes, length: int) -> bytes:
    if length > 255 * HASH_LEN:
        raise ValueError("length exceeds HKDF expand limit")

    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            prk,
            previous + info + bytes([counter]),
            HASH_NAME,
        ).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


class KeyDerivation:
    """Backward-compatible facade over the renamed key schedule helpers."""

    @staticmethod
    def derive_session_keys(shared_secrets: Sequence[bytes], transcript_hash: bytes) -> Dict[str, bytes]:
        handshake_secret = derive_handshake_secret(shared_secrets)
        handshake_traffic = derive_handshake_traffic_secrets(handshake_secret, transcript_hash)
        finished_keys = derive_finished_keys(
            handshake_traffic["client_handshake_traffic_secret"],
            handshake_traffic["server_handshake_traffic_secret"],
        )
        application_traffic = derive_application_traffic_secrets(handshake_secret, transcript_hash)

        return {
            "client_write_key": application_traffic["client_application_traffic_secret"],
            "server_write_key": application_traffic["server_application_traffic_secret"],
            "session_key": hkdf_expand_label(handshake_secret, b"session", transcript_hash, HASH_LEN),
            "pop_key": hkdf_expand_label(handshake_secret, b"pop", transcript_hash, HASH_LEN),
            **handshake_traffic,
            **finished_keys,
            **application_traffic,
        }

    @staticmethod
    def derive_single_key(secret: bytes, context: bytes) -> bytes:
        return hkdf_expand_label(secret, b"single", context, HASH_LEN)

    @staticmethod
    def compute_transcript_hash(messages: Sequence[bytes]) -> bytes:
        return compute_transcript_hash(messages)


__all__ = [
    "HASH_LEN",
    "KeyDerivation",
    "compute_transcript_hash",
    "derive_application_traffic_secrets",
    "derive_finished_keys",
    "derive_handshake_secret",
    "derive_handshake_traffic_secrets",
    "hkdf_expand_label",
    "hkdf_extract",
]
