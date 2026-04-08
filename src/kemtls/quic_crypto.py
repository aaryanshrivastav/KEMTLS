"""AEAD packet protection helpers for the QUIC-style KEMTLS transport core."""

from __future__ import annotations

from dataclasses import dataclass

from .quic_packets import encode_header
from .record_layer import protect as protect_record_payload
from .record_layer import unprotect as unprotect_record_payload


def build_packet_aad(
    *,
    packet_type: int,
    connection_id: bytes,
    packet_number: int,
    epoch: int = 0,
    payload_length: int = 0,
) -> bytes:
    return encode_header(
        packet_type=packet_type,
        connection_id=connection_id,
        packet_number=packet_number,
        epoch=epoch,
        payload_length=payload_length,
    )


def protect_packet(
    key: bytes,
    iv: bytes,
    packet_number: int,
    payload: bytes,
    aad: bytes,
) -> bytes:
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if not isinstance(aad, bytes):
        raise TypeError("aad must be bytes")
    return protect_record_payload(key, iv, packet_number, payload, aad)


def unprotect_packet(
    key: bytes,
    iv: bytes,
    packet_number: int,
    ciphertext: bytes,
    aad: bytes,
) -> bytes:
    if not isinstance(ciphertext, bytes):
        raise TypeError("ciphertext must be bytes")
    if not isinstance(aad, bytes):
        raise TypeError("aad must be bytes")
    return unprotect_record_payload(key, iv, packet_number, ciphertext, aad)


@dataclass
class QUICPacketProtector:
    key: bytes
    iv: bytes

    def protect_packet(self, packet_number: int, payload: bytes, aad: bytes) -> bytes:
        return protect_packet(self.key, self.iv, packet_number, payload, aad)

    def unprotect_packet(self, packet_number: int, ciphertext: bytes, aad: bytes) -> bytes:
        return unprotect_packet(self.key, self.iv, packet_number, ciphertext, aad)


__all__ = [
    "QUICPacketProtector",
    "build_packet_aad",
    "protect_packet",
    "unprotect_packet",
]
