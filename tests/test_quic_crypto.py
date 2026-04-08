import pytest

from kemtls.quic_crypto import (
    QUICPacketProtector,
    build_packet_aad,
    protect_packet,
    unprotect_packet,
)
from kemtls.quic_packets import APP_DATA, HANDSHAKE


def test_protect_packet_roundtrip():
    key = b"K" * 32
    iv = b"I" * 12
    aad = build_packet_aad(
        packet_type=APP_DATA,
        connection_id=b"conn-1",
        packet_number=4,
        epoch=1,
        payload_length=len(b"hello"),
    )

    ciphertext = protect_packet(key, iv, 4, b"hello", aad)
    plaintext = unprotect_packet(key, iv, 4, ciphertext, aad)

    assert plaintext == b"hello"


def test_packet_protector_uses_packet_number_in_nonce():
    protector = QUICPacketProtector(b"K" * 32, b"I" * 12)
    aad = build_packet_aad(
        packet_type=HANDSHAKE,
        connection_id=b"conn-1",
        packet_number=1,
        payload_length=len(b"same-payload"),
    )

    ciphertext_1 = protector.protect_packet(1, b"same-payload", aad)
    ciphertext_2 = protector.protect_packet(2, b"same-payload", aad)

    assert ciphertext_1 != ciphertext_2


def test_unprotect_packet_rejects_aad_mismatch():
    key = b"K" * 32
    iv = b"I" * 12
    good_aad = build_packet_aad(
        packet_type=APP_DATA,
        connection_id=b"conn-1",
        packet_number=9,
        payload_length=len(b"hello"),
    )
    bad_aad = build_packet_aad(
        packet_type=APP_DATA,
        connection_id=b"conn-2",
        packet_number=9,
        payload_length=len(b"hello"),
    )

    ciphertext = protect_packet(key, iv, 9, b"hello", good_aad)

    with pytest.raises(ValueError, match="authentication tag verification failed"):
        unprotect_packet(key, iv, 9, ciphertext, bad_aad)


def test_unprotect_packet_rejects_packet_number_mismatch():
    key = b"K" * 32
    iv = b"I" * 12
    aad = build_packet_aad(
        packet_type=APP_DATA,
        connection_id=b"conn-1",
        packet_number=3,
        payload_length=len(b"hello"),
    )

    ciphertext = protect_packet(key, iv, 3, b"hello", aad)

    with pytest.raises(ValueError, match="authentication tag verification failed"):
        unprotect_packet(key, iv, 4, ciphertext, aad)
