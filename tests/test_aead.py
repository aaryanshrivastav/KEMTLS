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


def test_rust_and_python_fallback_paths_match(monkeypatch):
    import rust_ext

    key = b"\x01" * KEY_SIZE
    nonce = b"\x02" * NONCE_SIZE
    plaintext = b"record payload"
    aad = b"header-aad"

    rust_ciphertext = seal(key, nonce, plaintext, aad)
    rust_plaintext = open_(key, nonce, rust_ciphertext, aad)

    original_core = rust_ext._core
    original_flag = rust_ext.HAS_RUST_BACKEND
    monkeypatch.setattr(rust_ext, "_core", None)
    monkeypatch.setattr(rust_ext, "HAS_RUST_BACKEND", False)
    try:
        py_ciphertext = seal(key, nonce, plaintext, aad)
        py_plaintext = open_(key, nonce, py_ciphertext, aad)
    finally:
        monkeypatch.setattr(rust_ext, "_core", original_core)
        monkeypatch.setattr(rust_ext, "HAS_RUST_BACKEND", original_flag)

    assert rust_plaintext == plaintext
    assert py_plaintext == plaintext
    # Nonce+key+aad are identical, so outputs should match across implementations.
    assert rust_ciphertext == py_ciphertext
