import pytest

from kemtls.quic_packets import (
    ACK,
    APP_DATA,
    CONNECTION_CLOSE,
    HANDSHAKE,
    INITIAL,
    QUICPacket,
    decode_packet,
    encode_packet,
)


@pytest.mark.parametrize("packet_type", [INITIAL, HANDSHAKE, APP_DATA, ACK, CONNECTION_CLOSE])
def test_encode_decode_packet_roundtrip(packet_type):
    encoded = encode_packet(
        packet_type=packet_type,
        connection_id=b"conn-1",
        packet_number=7,
        payload=b"payload",
        epoch=2,
    )

    decoded = decode_packet(encoded)

    assert decoded == QUICPacket(
        packet_type=packet_type,
        connection_id=b"conn-1",
        packet_number=7,
        payload=b"payload",
        epoch=2,
    )


def test_decode_packet_rejects_short_packet():
    with pytest.raises(ValueError, match="packet too short"):
        decode_packet(b"\x01\x02")


def test_decode_packet_rejects_invalid_packet_type():
    encoded = bytearray(
        encode_packet(
            packet_type=INITIAL,
            connection_id=b"conn-1",
            packet_number=1,
            payload=b"payload",
        )
    )
    encoded[1] = 0xFF

    with pytest.raises(ValueError, match="unsupported packet_type"):
        decode_packet(bytes(encoded))


def test_decode_packet_rejects_invalid_version():
    encoded = bytearray(
        encode_packet(
            packet_type=HANDSHAKE,
            connection_id=b"conn-1",
            packet_number=1,
            payload=b"payload",
        )
    )
    encoded[0] = 0x09

    with pytest.raises(ValueError, match="unsupported packet version"):
        decode_packet(bytes(encoded))


def test_decode_packet_rejects_length_mismatch():
    encoded = encode_packet(
        packet_type=APP_DATA,
        connection_id=b"conn-1",
        packet_number=5,
        payload=b"payload",
    )

    with pytest.raises(ValueError, match="packet length mismatch"):
        decode_packet(encoded[:-1])


def test_encode_packet_rejects_empty_connection_id():
    with pytest.raises(ValueError, match="connection_id must not be empty"):
        encode_packet(
            packet_type=ACK,
            connection_id=b"",
            packet_number=0,
            payload=b"",
        )
