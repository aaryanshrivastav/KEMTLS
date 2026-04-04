import pytest

from crypto.aead import KEY_SIZE, NONCE_SIZE, open_, seal, xor_iv_with_seq

pytest.importorskip("cryptography")


def test_aead_roundtrip():
    key = b"\x01" * KEY_SIZE
    nonce = b"\x02" * NONCE_SIZE
    plaintext = b"record payload"
    aad = b"\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x10"

    ciphertext = seal(key, nonce, plaintext, aad)
    recovered = open_(key, nonce, ciphertext, aad)

    assert recovered == plaintext


def test_invalid_tag_failure():
    key = b"\x01" * KEY_SIZE
    nonce = b"\x02" * NONCE_SIZE
    plaintext = b"record payload"
    aad = b"header"
    ciphertext = bytearray(seal(key, nonce, plaintext, aad))
    ciphertext[-1] ^= 0x01

    with pytest.raises(ValueError, match="authentication tag verification failed"):
        open_(key, nonce, bytes(ciphertext), aad)


def test_xor_iv_with_seq_is_deterministic():
    iv = bytes(range(NONCE_SIZE))

    first = xor_iv_with_seq(iv, 7)
    second = xor_iv_with_seq(iv, 7)
    third = xor_iv_with_seq(iv, 8)

    assert first == second
    assert first != third
