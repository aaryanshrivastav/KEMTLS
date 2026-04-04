import pytest

from crypto.ml_kem import MLKEM768


class _FakeKEMHandle:
    def __init__(self, algorithm: str, secret_key: bytes | None = None):
        assert algorithm == MLKEM768.ALGORITHM
        self.secret_key = secret_key

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def generate_keypair(self) -> bytes:
        return b"P" * MLKEM768.PUBLIC_KEY_SIZE

    def export_secret_key(self) -> bytes:
        return b"S" * MLKEM768.SECRET_KEY_SIZE

    def encap_secret(self, public_key: bytes):
        marker = bytes([(public_key[0] + len(public_key)) % 256])
        ciphertext = marker * MLKEM768.CIPHERTEXT_SIZE
        shared_secret = (marker + b"\xAA" * (MLKEM768.SHARED_SECRET_SIZE - 1))
        return ciphertext, shared_secret

    def decap_secret(self, ciphertext: bytes):
        marker = ciphertext[:1]
        return marker + b"\xAA" * (MLKEM768.SHARED_SECRET_SIZE - 1)


class _FakeOQSModule:
    KeyEncapsulation = _FakeKEMHandle


def test_generate_keypair_returns_expected_sizes(monkeypatch):
    monkeypatch.setattr("crypto.ml_kem._load_oqs", lambda: _FakeOQSModule)

    public_key, secret_key = MLKEM768.generate_keypair()

    assert len(public_key) == MLKEM768.PUBLIC_KEY_SIZE
    assert len(secret_key) == MLKEM768.SECRET_KEY_SIZE


def test_encap_decap_roundtrip(monkeypatch):
    monkeypatch.setattr("crypto.ml_kem._load_oqs", lambda: _FakeOQSModule)

    public_key, secret_key = MLKEM768.generate_keypair()
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
    counter = {"value": 0}

    class _ChangingKEMHandle(_FakeKEMHandle):
        def encap_secret(self, public_key: bytes):
            counter["value"] += 1
            marker = bytes([counter["value"]])
            ciphertext = marker * MLKEM768.CIPHERTEXT_SIZE
            shared_secret = marker + b"\xBB" * (MLKEM768.SHARED_SECRET_SIZE - 1)
            return ciphertext, shared_secret

    class _ChangingOQSModule:
        KeyEncapsulation = _ChangingKEMHandle

    monkeypatch.setattr("crypto.ml_kem._load_oqs", lambda: _ChangingOQSModule)
    public_key, _ = MLKEM768.generate_keypair()

    ciphertext_1, shared_secret_1 = MLKEM768.encapsulate(public_key)
    ciphertext_2, shared_secret_2 = MLKEM768.encapsulate(public_key)

    assert ciphertext_1 != ciphertext_2
    assert shared_secret_1 != shared_secret_2
