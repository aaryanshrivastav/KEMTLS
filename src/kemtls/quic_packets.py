"""Packet codec for the QUIC-style KEMTLS transport core."""

from __future__ import annotations

import struct
from dataclasses import dataclass


PACKET_VERSION = 1

INITIAL = 0x00
HANDSHAKE = 0x01
APP_DATA = 0x02
ACK = 0x03
CONNECTION_CLOSE = 0x04

PACKET_TYPES = {
    INITIAL,
    HANDSHAKE,
    APP_DATA,
    ACK,
    CONNECTION_CLOSE,
}

_HEADER_STRUCT = struct.Struct(">BBBBQI")
_MAX_CONNECTION_ID_LEN = 255


@dataclass(frozen=True)
class QUICPacket:
    packet_type: int
    connection_id: bytes
    packet_number: int
    payload: bytes
    epoch: int = 0
    version: int = PACKET_VERSION


def encode_header(
    *,
    packet_type: int,
    connection_id: bytes,
    packet_number: int,
    epoch: int = 0,
    payload_length: int = 0,
    version: int = PACKET_VERSION,
) -> bytes:
    _validate_packet_type(packet_type)
    _validate_connection_id(connection_id)
    _validate_packet_number(packet_number)
    _validate_epoch(epoch)
    _validate_payload_length(payload_length)
    _validate_version(version)

    return _HEADER_STRUCT.pack(
        version,
        packet_type,
        epoch,
        len(connection_id),
        packet_number,
        payload_length,
    ) + connection_id


def encode_packet(
    *,
    packet_type: int,
    connection_id: bytes,
    packet_number: int,
    payload: bytes,
    epoch: int = 0,
    version: int = PACKET_VERSION,
) -> bytes:
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")

    header = encode_header(
        packet_type=packet_type,
        connection_id=connection_id,
        packet_number=packet_number,
        epoch=epoch,
        payload_length=len(payload),
        version=version,
    )
    return header + payload


def decode_packet(data: bytes) -> QUICPacket:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if len(data) < _HEADER_STRUCT.size:
        raise ValueError("packet too short")

    version, packet_type, epoch, connection_id_len, packet_number, payload_length = _HEADER_STRUCT.unpack(
        data[:_HEADER_STRUCT.size]
    )
    _validate_version(version)
    _validate_packet_type(packet_type)
    _validate_epoch(epoch)

    if connection_id_len > _MAX_CONNECTION_ID_LEN:
        raise ValueError("connection_id is too long")

    header_len = _HEADER_STRUCT.size + connection_id_len
    expected_len = header_len + payload_length
    if len(data) != expected_len:
        raise ValueError("packet length mismatch")

    connection_id = data[_HEADER_STRUCT.size:header_len]
    payload = data[header_len:expected_len]
    _validate_connection_id(connection_id)

    return QUICPacket(
        packet_type=packet_type,
        connection_id=connection_id,
        packet_number=packet_number,
        payload=payload,
        epoch=epoch,
        version=version,
    )


def _validate_packet_type(packet_type: int) -> None:
    if not isinstance(packet_type, int):
        raise TypeError("packet_type must be an integer")
    if packet_type not in PACKET_TYPES:
        raise ValueError(f"unsupported packet_type: {packet_type}")


def _validate_connection_id(connection_id: bytes) -> None:
    if not isinstance(connection_id, bytes):
        raise TypeError("connection_id must be bytes")
    if not connection_id:
        raise ValueError("connection_id must not be empty")
    if len(connection_id) > _MAX_CONNECTION_ID_LEN:
        raise ValueError("connection_id is too long")


def _validate_packet_number(packet_number: int) -> None:
    if not isinstance(packet_number, int):
        raise TypeError("packet_number must be an integer")
    if packet_number < 0 or packet_number >= 1 << 64:
        raise ValueError("packet_number must be between 0 and 2^64 - 1")


def _validate_epoch(epoch: int) -> None:
    if not isinstance(epoch, int):
        raise TypeError("epoch must be an integer")
    if epoch < 0 or epoch > 255:
        raise ValueError("epoch must be between 0 and 255")


def _validate_payload_length(payload_length: int) -> None:
    if not isinstance(payload_length, int):
        raise TypeError("payload_length must be an integer")
    if payload_length < 0 or payload_length >= 1 << 32:
        raise ValueError("payload_length must be between 0 and 2^32 - 1")


def _validate_version(version: int) -> None:
    if not isinstance(version, int):
        raise TypeError("version must be an integer")
    if version != PACKET_VERSION:
        raise ValueError(f"unsupported packet version: {version}")


__all__ = [
    "PACKET_VERSION",
    "INITIAL",
    "HANDSHAKE",
    "APP_DATA",
    "ACK",
    "CONNECTION_CLOSE",
    "QUICPacket",
    "encode_header",
    "encode_packet",
    "decode_packet",
]
