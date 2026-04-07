"""Python bridge for the optional Rust acceleration backend."""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Tuple

try:
    import kemtls_core as _core
except ImportError:
    _core = None


HAS_RUST_BACKEND = _core is not None


class _KeyScheduleBackend:
    @staticmethod
    def hkdf_extract(salt: bytes, ikm: bytes, fallback: Optional[Callable[[bytes, bytes], bytes]] = None) -> bytes:
        if _core is not None:
            return _core.hkdf_extract(salt, ikm)
        if fallback is not None:
            return fallback(salt, ikm)
        raise RuntimeError("Rust backend unavailable and no fallback provided")

    @staticmethod
    def hkdf_expand(
        prk: bytes,
        info: bytes,
        length: int,
        fallback: Optional[Callable[[bytes, bytes, int], bytes]] = None,
    ) -> bytes:
        if _core is not None:
            return _core.hkdf_expand(prk, info, length)
        if fallback is not None:
            return fallback(prk, info, length)
        raise RuntimeError("Rust backend unavailable and no fallback provided")

    @staticmethod
    def transcript_hash(data: bytes, fallback: Optional[Callable[[bytes], bytes]] = None) -> bytes:
        if _core is not None:
            return _core.transcript_hash(data)
        if fallback is not None:
            return fallback(data)
        raise RuntimeError("Rust backend unavailable and no fallback provided")

    @staticmethod
    def transcript_hash_many(
        messages: list[bytes],
        fallback: Optional[Callable[[list[bytes]], bytes]] = None,
    ) -> bytes:
        if _core is not None:
            return _core.transcript_hash_many(messages)
        if fallback is not None:
            return fallback(messages)
        raise RuntimeError("Rust backend unavailable and no fallback provided")


class _SerializationBackend:
    @staticmethod
    def canonical_json_encode(
        obj: Dict[str, Any],
        fallback: Optional[Callable[[Dict[str, Any]], bytes]] = None,
    ) -> bytes:
        if _core is not None:
            return _core.canonical_json_encode(obj)
        if fallback is not None:
            return fallback(obj)
        raise RuntimeError("Rust backend unavailable and no fallback provided")

    @staticmethod
    def canonical_json_decode(
        data: bytes,
        fallback: Optional[Callable[[bytes], Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        if _core is not None:
            return _core.canonical_json_decode(data)
        if fallback is not None:
            return fallback(data)
        raise RuntimeError("Rust backend unavailable and no fallback provided")


class _RecordLayerBackend:
    @staticmethod
    def frame_record(
        seq: int,
        payload: bytes,
        fallback: Optional[Callable[[int, bytes], bytes]] = None,
    ) -> bytes:
        if _core is not None:
            return _core.frame_record(seq, payload)
        if fallback is not None:
            return fallback(seq, payload)
        raise RuntimeError("Rust backend unavailable and no fallback provided")

    @staticmethod
    def parse_record(
        data: bytes,
        fallback: Optional[Callable[[bytes], Tuple[int, bytes]]] = None,
    ) -> Tuple[int, bytes]:
        if _core is not None:
            return _core.parse_record(data)
        if fallback is not None:
            return fallback(data)
        raise RuntimeError("Rust backend unavailable and no fallback provided")


class _HandshakeBackend:
    @staticmethod
    def hmac_sha256(
        key: bytes,
        data: bytes,
        fallback: Optional[Callable[[bytes, bytes], bytes]] = None,
    ) -> bytes:
        if _core is not None:
            return _core.hmac_sha256(key, data)
        if fallback is not None:
            return fallback(key, data)
        raise RuntimeError("Rust backend unavailable and no fallback provided")

    @staticmethod
    def client_hello(
        client_random: str,
        expected_identity: str,
        modes: list[str],
        fallback: Optional[Callable[[str, str, list[str]], bytes]] = None,
    ) -> bytes:
        if _core is not None:
            return _core.handshake_client_hello(client_random, expected_identity, modes)
        if fallback is not None:
            return fallback(client_random, expected_identity, modes)
        raise RuntimeError("Rust backend unavailable and no fallback provided")

    @staticmethod
    def client_key_exchange(
        ct_ephemeral: bytes,
        ct_longterm: bytes,
        fallback: Optional[Callable[[bytes, bytes], bytes]] = None,
    ) -> bytes:
        if _core is not None:
            return _core.handshake_client_key_exchange(ct_ephemeral, ct_longterm)
        if fallback is not None:
            return fallback(ct_ephemeral, ct_longterm)
        raise RuntimeError("Rust backend unavailable and no fallback provided")

    @staticmethod
    def finished(
        message_type: str,
        mac: bytes,
        fallback: Optional[Callable[[str, bytes], bytes]] = None,
    ) -> bytes:
        if _core is not None:
            return _core.handshake_finished(message_type, mac)
        if fallback is not None:
            return fallback(message_type, mac)
        raise RuntimeError("Rust backend unavailable and no fallback provided")


class _HttpBackend:
    @staticmethod
    def parse_http_request(
        raw_data: bytes,
        fallback: Optional[Callable[[bytes], Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        if _core is not None:
            return _core.parse_http_request(raw_data)
        if fallback is not None:
            return fallback(raw_data)
        raise RuntimeError("Rust backend unavailable and no fallback provided")

    @staticmethod
    def parse_http_response(
        raw_data: bytes,
        fallback: Optional[Callable[[bytes], Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        if _core is not None:
            return _core.parse_http_response(raw_data)
        if fallback is not None:
            return fallback(raw_data)
        raise RuntimeError("Rust backend unavailable and no fallback provided")


class _JwtBackend:
    @staticmethod
    def split_jwt(
        token: str,
        fallback: Optional[Callable[[str], Tuple[str, str, str]]] = None,
    ) -> Tuple[str, str, str]:
        if _core is not None:
            return _core.split_jwt(token)
        if fallback is not None:
            return fallback(token)
        raise RuntimeError("Rust backend unavailable and no fallback provided")

    @staticmethod
    def jwt_signing_input(
        header_b64: str,
        payload_b64: str,
        fallback: Optional[Callable[[str, str], bytes]] = None,
    ) -> bytes:
        if _core is not None:
            return _core.jwt_signing_input(header_b64, payload_b64)
        if fallback is not None:
            return fallback(header_b64, payload_b64)
        raise RuntimeError("Rust backend unavailable and no fallback provided")


class _HashingBackend:
    @staticmethod
    def sha256_digest(
        data: bytes,
        fallback: Optional[Callable[[bytes], bytes]] = None,
    ) -> bytes:
        if _core is not None:
            return _core.sha256_digest(data)
        if fallback is not None:
            return fallback(data)
        raise RuntimeError("Rust backend unavailable and no fallback provided")

    @staticmethod
    def sha256_hex(
        data: str,
        fallback: Optional[Callable[[str], str]] = None,
    ) -> str:
        if _core is not None:
            return _core.sha256_hex(data)
        if fallback is not None:
            return fallback(data)
        raise RuntimeError("Rust backend unavailable and no fallback provided")


class _AeadBackend:
    @staticmethod
    def seal(
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes,
        fallback: Optional[Callable[[bytes, bytes, bytes, bytes], bytes]] = None,
    ) -> bytes:
        if _core is not None:
            return _core.aead_seal(key, nonce, plaintext, aad)
        if fallback is not None:
            return fallback(key, nonce, plaintext, aad)
        raise RuntimeError("Rust backend unavailable and no fallback provided")

    @staticmethod
    def open(
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        aad: bytes,
        fallback: Optional[Callable[[bytes, bytes, bytes, bytes], bytes]] = None,
    ) -> bytes:
        if _core is not None:
            return _core.aead_open(key, nonce, ciphertext, aad)
        if fallback is not None:
            return fallback(key, nonce, ciphertext, aad)
        raise RuntimeError("Rust backend unavailable and no fallback provided")

    @staticmethod
    def xor_iv_with_seq(
        iv: bytes,
        seq: int,
        fallback: Optional[Callable[[bytes, int], bytes]] = None,
    ) -> bytes:
        if _core is not None:
            return _core.xor_iv_with_seq(iv, seq)
        if fallback is not None:
            return fallback(iv, seq)
        raise RuntimeError("Rust backend unavailable and no fallback provided")


def get_build_profile() -> str:
    """Return backend build profile: 'release', 'debug', or 'python-fallback'."""
    if _core is None:
        return "python-fallback"
    build_profile = getattr(_core, "build_profile", None)
    if callable(build_profile):
        return str(build_profile())
    return "unknown"


key_schedule = _KeyScheduleBackend()
serialization = _SerializationBackend()
record_layer = _RecordLayerBackend()
handshake = _HandshakeBackend()
http = _HttpBackend()
jwt = _JwtBackend()
hashing = _HashingBackend()
aead = _AeadBackend()


__all__ = [
    "HAS_RUST_BACKEND",
    "get_build_profile",
    "key_schedule",
    "serialization",
    "record_layer",
    "handshake",
    "http",
    "jwt",
    "hashing",
    "aead",
]
