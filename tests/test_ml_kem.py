import pytest

from crypto.ml_kem import MLKEM768


def test_generate_keypair_returns_expected_sizes(mlkem_keypair):
    public_key, secret_key = mlkem_keypair

    assert len(public_key) == MLKEM768.PUBLIC_KEY_SIZE
    assert len(secret_key) == MLKEM768.SECRET_KEY_SIZE


def test_encap_decap_roundtrip(mlkem_keypair):
    public_key, secret_key = mlkem_keypair
    ciphertext, shared_secret_sender = MLKEM768.encapsulate(public_key)
    shared_secret_receiver = MLKEM768.decapsulate(secret_key, ciphertext)

    assert shared_secret_sender == shared_secret_receiver
    assert len(ciphertext) == MLKEM768.CIPHERTEXT_SIZE
    assert len(shared_secret_sender) == MLKEM768.SHARED_SECRET_SIZE


def test_invalid_size_rejection_happens_before_backend_load(monkeypatch):
    def _unexpected_load():
        raise AssertionError("backend should not load for invalid public key sizes")

    monkeypatch.setattr("crypto.ml_kem._load_oqs", _unexpected_load)

    with pytest.raises(ValueError, match="public_key"):
        MLKEM768.encapsulate(b"short")


def test_different_encapsulations_can_produce_distinct_values(monkeypatch):
    public_key, _ = MLKEM768.generate_keypair()

    ciphertext_1, shared_secret_1 = MLKEM768.encapsulate(public_key)
    ciphertext_2, shared_secret_2 = MLKEM768.encapsulate(public_key)

    assert ciphertext_1 != ciphertext_2
    assert shared_secret_1 != shared_secret_2
