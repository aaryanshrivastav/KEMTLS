import pytest

from crypto.key_schedule import (
    HASH_LEN,
    compute_transcript_hash,
    derive_application_traffic_secrets,
    derive_finished_keys,
    derive_handshake_secret,
    derive_handshake_traffic_secrets,
    hkdf_expand_label,
)


def test_transcript_hash_is_deterministic():
    messages = [b"ClientHello", b"ServerHello", b"ClientKeyExchange"]

    first = compute_transcript_hash(messages)
    second = compute_transcript_hash(messages)

    assert first == second
    assert len(first) == HASH_LEN


def test_hkdf_expand_label_separates_labels():
    secret = b"\x01" * HASH_LEN
    context = b"\x02" * HASH_LEN

    first = hkdf_expand_label(secret, b"label-a", context, HASH_LEN)
    second = hkdf_expand_label(secret, b"label-b", context, HASH_LEN)

    assert first != second


def test_handshake_and_application_secrets_differ():
    transcript_1 = compute_transcript_hash([b"ClientHello", b"ServerHello", b"ClientKeyExchange"])
    transcript_3 = compute_transcript_hash(
        [b"ClientHello", b"ServerHello", b"ClientKeyExchange", b"ServerFinished", b"ClientFinished"]
    )
    handshake_secret = derive_handshake_secret([b"\x0A" * HASH_LEN, b"\x0B" * HASH_LEN])

    handshake_traffic = derive_handshake_traffic_secrets(handshake_secret, transcript_1)
    finished_keys = derive_finished_keys(
        handshake_traffic["client_handshake_traffic_secret"],
        handshake_traffic["server_handshake_traffic_secret"],
    )
    application_traffic = derive_application_traffic_secrets(handshake_secret, transcript_3)

    assert handshake_traffic["client_handshake_traffic_secret"] != application_traffic["client_application_traffic_secret"]
    assert handshake_traffic["server_handshake_traffic_secret"] != application_traffic["server_application_traffic_secret"]
    assert finished_keys["client_finished_key"] != application_traffic["client_application_traffic_secret"]


def test_application_secret_derivation_requires_transcript_3_shape():
    handshake_secret = derive_handshake_secret([b"\x11" * HASH_LEN, b"\x22" * HASH_LEN])
    transcript_1 = compute_transcript_hash([b"ClientHello", b"ServerHello", b"ClientKeyExchange"])

    application_from_transcript_1 = derive_application_traffic_secrets(handshake_secret, transcript_1)
    transcript_3 = compute_transcript_hash(
        [b"ClientHello", b"ServerHello", b"ClientKeyExchange", b"ServerFinished", b"ClientFinished"]
    )
    application_from_transcript_3 = derive_application_traffic_secrets(handshake_secret, transcript_3)

    assert application_from_transcript_1 != application_from_transcript_3


def test_handshake_secret_rejects_empty_input():
    with pytest.raises(ValueError, match="must not be empty"):
        derive_handshake_secret([])
