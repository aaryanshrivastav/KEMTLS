import pytest

from crypto.ml_dsa import MLDSA65


def test_sign_verify_roundtrip(mldsa_keypair):
    public_key, secret_key = mldsa_keypair
    message = b"post-quantum message"
    signature = MLDSA65.sign(secret_key, message)

    assert MLDSA65.verify(public_key, message, signature) is True


def test_tamper_detection(mldsa_keypair):
    public_key, secret_key = mldsa_keypair
    signature = MLDSA65.sign(secret_key, b"original")

    assert MLDSA65.verify(public_key, b"tampered", signature) is False


def test_wrong_key_rejection_by_size_happens_locally(monkeypatch):
    def _unexpected_load():
        raise AssertionError("backend should not load for invalid public key sizes")

    monkeypatch.setattr("crypto.ml_dsa._load_ml_dsa_backend", _unexpected_load)

    with pytest.raises(ValueError, match="public_key"):
        MLDSA65.verify(b"bad", b"message", b"S" * MLDSA65.SIGNATURE_SIZE)


def test_jwk_import_export_roundtrip():
    public_key = b"P" * MLDSA65.PUBLIC_KEY_SIZE

    jwk = MLDSA65.public_key_to_jwk(public_key, kid="sig-1")
    recovered = MLDSA65.jwk_to_public_key(jwk)

    assert jwk["alg"] == MLDSA65.ALGORITHM
    assert jwk["kid"] == "sig-1"
    assert recovered == public_key


def test_jwk_validation_rejects_wrong_algorithm():
    jwk = {
        "kty": MLDSA65.JWK_KEY_TYPE,
        "alg": "wrong",
        "use": "sig",
        "x": "QQ",
    }

    with pytest.raises(ValueError, match="algorithm"):
        MLDSA65.jwk_to_public_key(jwk)
