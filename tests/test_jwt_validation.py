import time

import pytest

from crypto.ml_dsa import MLDSA65
from oidc.jwt_handler import ACCESS_TOKEN_TYPE, ID_TOKEN_TYPE, PQJWT
from oidc.session_binding import build_access_token_binding_claim
from utils.encoding import base64url_encode


def _fake_sign(secret_key: bytes, message: bytes) -> bytes:
    return (message[:1] or b"\x00") + b"\xAA" * (MLDSA65.SIGNATURE_SIZE - 1)


def _fake_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    return signature == _fake_sign(b"", message)


@pytest.fixture
def pqjwt(monkeypatch):
    monkeypatch.setattr("oidc.jwt_handler.MLDSA65.sign", _fake_sign)
    monkeypatch.setattr("oidc.jwt_handler.MLDSA65.verify", _fake_verify)
    return PQJWT()


def test_id_and_access_tokens_remain_standard_shaped(pqjwt):
    class _Session:
        session_binding_id = b"\x01" * 32
        refresh_binding_id = b"\x02" * 32

    id_token = pqjwt.create_id_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "client123",
            "exp": int(time.time()) + 600,
        },
        b"S" * MLDSA65.SECRET_KEY_SIZE,
    )
    access_token = pqjwt.create_access_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "api://resource",
            "exp": int(time.time()) + 600,
        },
        b"S" * MLDSA65.SECRET_KEY_SIZE,
        cnf_claim=build_access_token_binding_claim(_Session()),
    )

    id_header, _ = pqjwt.verify_jwt(
        id_token,
        b"P" * MLDSA65.PUBLIC_KEY_SIZE,
        expected_type=ID_TOKEN_TYPE,
    )
    access_header, access_payload = pqjwt.verify_jwt(
        access_token,
        b"P" * MLDSA65.PUBLIC_KEY_SIZE,
        expected_type=ACCESS_TOKEN_TYPE,
    )

    assert id_token.count(".") == 2
    assert access_token.count(".") == 2
    assert id_header["typ"] == ID_TOKEN_TYPE
    assert access_header["typ"] == ACCESS_TOKEN_TYPE
    assert access_payload["cnf"]["kmt"] == "kemtls-exporter-v1"


def test_jwt_validation_rejects_wrong_claims_and_times(pqjwt):
    token = pqjwt.create_id_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "client123",
            "nonce": "nonce-1",
            "nbf": int(time.time()) - 10,
            "exp": int(time.time()) + 10,
        },
        b"S" * MLDSA65.SECRET_KEY_SIZE,
    )

    with pytest.raises(ValueError, match="issuer mismatch"):
        pqjwt.validate_id_token(token, b"P" * MLDSA65.PUBLIC_KEY_SIZE, issuer="https://wrong")
    with pytest.raises(ValueError, match="audience mismatch"):
        pqjwt.validate_id_token(token, b"P" * MLDSA65.PUBLIC_KEY_SIZE, audience="wrong")
    with pytest.raises(ValueError, match="nonce mismatch"):
        pqjwt.validate_id_token(token, b"P" * MLDSA65.PUBLIC_KEY_SIZE, nonce="wrong")

    expired = pqjwt.create_id_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "client123",
            "exp": int(time.time()) - 1,
        },
        b"S" * MLDSA65.SECRET_KEY_SIZE,
    )
    future = pqjwt.create_id_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "client123",
            "nbf": int(time.time()) + 600,
            "exp": int(time.time()) + 1200,
        },
        b"S" * MLDSA65.SECRET_KEY_SIZE,
    )

    with pytest.raises(ValueError, match="token expired"):
        pqjwt.validate_id_token(expired, b"P" * MLDSA65.PUBLIC_KEY_SIZE)
    with pytest.raises(ValueError, match="not yet valid"):
        pqjwt.validate_id_token(future, b"P" * MLDSA65.PUBLIC_KEY_SIZE)


def test_jwt_validation_rejects_bad_format_alg_signature_and_cnf(pqjwt):
    with pytest.raises(ValueError, match="invalid JWT format"):
        pqjwt.verify_jwt("bad-token", b"P" * MLDSA65.PUBLIC_KEY_SIZE)

    token = pqjwt.create_id_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "client123",
            "exp": int(time.time()) + 600,
        },
        b"S" * MLDSA65.SECRET_KEY_SIZE,
    )
    header_b64, payload_b64, signature_b64 = token.split(".")

    with pytest.raises(ValueError, match="unexpected JWT type"):
        pqjwt.verify_jwt(token, b"P" * MLDSA65.PUBLIC_KEY_SIZE, expected_type=ACCESS_TOKEN_TYPE)

    bad_header = base64url_encode(b'{"alg":"WRONG","kid":"x","typ":"JWT"}')
    bad_alg_token = ".".join([bad_header, payload_b64, signature_b64])
    with pytest.raises(ValueError, match="unsupported JWT algorithm"):
        pqjwt.verify_jwt(bad_alg_token, b"P" * MLDSA65.PUBLIC_KEY_SIZE)

    bad_signature = ".".join(
        [header_b64, payload_b64, base64url_encode(b"\x00" * MLDSA65.SIGNATURE_SIZE)]
    )
    with pytest.raises(ValueError, match="invalid JWT signature"):
        pqjwt.verify_jwt(bad_signature, b"P" * MLDSA65.PUBLIC_KEY_SIZE)

    with pytest.raises(ValueError, match="must only contain"):
        pqjwt.create_access_token(
            {"sub": "alice"},
            b"S" * MLDSA65.SECRET_KEY_SIZE,
            cnf_claim={"wrong": "shape"},
        )

    with pytest.raises(ValueError, match="must not override"):
        pqjwt.sign_jwt(
            {"sub": "alice"},
            b"S" * MLDSA65.SECRET_KEY_SIZE,
            extra_headers={"alg": "WRONG"},
        )
