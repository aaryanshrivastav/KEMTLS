import time

import pytest

from crypto.ml_dsa import MLDSA65
from utils.encoding import base64url_encode
from oidc.jwt_handler import ACCESS_TOKEN_TYPE, ID_TOKEN_TYPE, PQJWT
from oidc.session_binding import build_access_token_binding_claim


def _fake_sign(secret_key: bytes, message: bytes) -> bytes:
    marker = message[:1] or b"\x00"
    return marker + b"\xAA" * (MLDSA65.SIGNATURE_SIZE - 1)


def _fake_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    return signature == _fake_sign(b"", message)


@pytest.fixture
def pqjwt(monkeypatch):
    monkeypatch.setattr("oidc.jwt_handler.MLDSA65.sign", _fake_sign)
    monkeypatch.setattr("oidc.jwt_handler.MLDSA65.verify", _fake_verify)
    return PQJWT()


def test_valid_id_token_verification_retains_standard_jwt_shape(pqjwt):
    claims = {
        "iss": "https://issuer.example",
        "sub": "alice",
        "aud": "client-123",
        "exp": int(time.time()) + 600,
    }

    token = pqjwt.create_id_token(claims, b"S" * MLDSA65.SECRET_KEY_SIZE)
    header, payload = pqjwt.verify_jwt(
        token,
        b"P" * MLDSA65.PUBLIC_KEY_SIZE,
        expected_type=ID_TOKEN_TYPE,
    )

    assert token.count(".") == 2
    assert header["typ"] == ID_TOKEN_TYPE
    assert payload["sub"] == "alice"


def test_valid_access_token_verification_with_binding_claim(pqjwt):
    class _Session:
        session_binding_id = b"\x01" * 32
        refresh_binding_id = b"\x02" * 32

    claims = {
        "iss": "https://issuer.example",
        "sub": "alice",
        "aud": "api://resource",
        "exp": int(time.time()) + 600,
        "scope": "openid profile",
    }

    token = pqjwt.create_access_token(
        claims,
        b"S" * MLDSA65.SECRET_KEY_SIZE,
        cnf_claim=build_access_token_binding_claim(_Session()),
    )
    validated = pqjwt.validate_access_token(
        token,
        b"P" * MLDSA65.PUBLIC_KEY_SIZE,
        issuer="https://issuer.example",
        audience="api://resource",
    )

    assert validated["cnf"]["kmt"] == "kemtls-exporter-v1"
    assert pqjwt.verify_jwt(token, b"P" * MLDSA65.PUBLIC_KEY_SIZE, expected_type=ACCESS_TOKEN_TYPE)[0]["typ"] == ACCESS_TOKEN_TYPE


def test_wrong_issuer_or_audience_is_rejected(pqjwt):
    claims = {
        "iss": "https://issuer.example",
        "sub": "alice",
        "aud": "client-123",
        "exp": int(time.time()) + 600,
    }
    token = pqjwt.create_id_token(claims, b"S" * MLDSA65.SECRET_KEY_SIZE)

    with pytest.raises(ValueError, match="issuer mismatch"):
        pqjwt.validate_id_token(
            token,
            b"P" * MLDSA65.PUBLIC_KEY_SIZE,
            issuer="https://wrong.example",
        )

    with pytest.raises(ValueError, match="audience mismatch"):
        pqjwt.validate_id_token(
            token,
            b"P" * MLDSA65.PUBLIC_KEY_SIZE,
            audience="wrong-aud",
        )


def test_expired_token_is_rejected(pqjwt):
    claims = {
        "iss": "https://issuer.example",
        "sub": "alice",
        "aud": "client-123",
        "exp": int(time.time()) - 10,
    }
    token = pqjwt.create_id_token(claims, b"S" * MLDSA65.SECRET_KEY_SIZE)

    with pytest.raises(ValueError, match="token expired"):
        pqjwt.validate_id_token(token, b"P" * MLDSA65.PUBLIC_KEY_SIZE)


def test_nonce_mismatch_is_rejected(pqjwt):
    claims = {
        "iss": "https://issuer.example",
        "sub": "alice",
        "aud": "client-123",
        "nonce": "right-nonce",
        "exp": int(time.time()) + 600,
    }
    token = pqjwt.create_id_token(claims, b"S" * MLDSA65.SECRET_KEY_SIZE)

    with pytest.raises(ValueError, match="nonce mismatch"):
        pqjwt.validate_id_token(
            token,
            b"P" * MLDSA65.PUBLIC_KEY_SIZE,
            nonce="wrong-nonce",
        )


def test_not_yet_valid_token_is_rejected(pqjwt):
    claims = {
        "iss": "https://issuer.example",
        "sub": "alice",
        "aud": "client-123",
        "nbf": int(time.time()) + 600,
        "exp": int(time.time()) + 1200,
    }
    token = pqjwt.create_id_token(claims, b"S" * MLDSA65.SECRET_KEY_SIZE)

    with pytest.raises(ValueError, match="not yet valid"):
        pqjwt.validate_id_token(token, b"P" * MLDSA65.PUBLIC_KEY_SIZE)


def test_malformed_or_wrong_type_jwts_are_rejected(pqjwt):
    with pytest.raises(ValueError, match="invalid JWT format"):
        pqjwt.verify_jwt("bad-token", b"P" * MLDSA65.PUBLIC_KEY_SIZE)

    id_token = pqjwt.create_id_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "client-123",
            "exp": int(time.time()) + 600,
        },
        b"S" * MLDSA65.SECRET_KEY_SIZE,
    )
    with pytest.raises(ValueError, match="unexpected JWT type"):
        pqjwt.verify_jwt(
            id_token,
            b"P" * MLDSA65.PUBLIC_KEY_SIZE,
            expected_type=ACCESS_TOKEN_TYPE,
        )


def test_invalid_signature_and_bad_algorithm_are_rejected(pqjwt):
    claims = {
        "iss": "https://issuer.example",
        "sub": "alice",
        "aud": "client-123",
        "exp": int(time.time()) + 600,
    }
    token = pqjwt.create_id_token(claims, b"S" * MLDSA65.SECRET_KEY_SIZE)
    header_b64, payload_b64, signature_b64 = token.split(".")

    bad_signature = ".".join([header_b64, payload_b64, base64url_encode(b"\x00" * MLDSA65.SIGNATURE_SIZE)])
    with pytest.raises(ValueError, match="invalid JWT signature"):
        pqjwt.verify_jwt(bad_signature, b"P" * MLDSA65.PUBLIC_KEY_SIZE)

    bad_header = base64url_encode(b'{"alg":"WRONG","kid":"x","typ":"JWT"}')
    bad_alg_token = ".".join([bad_header, payload_b64, signature_b64])
    with pytest.raises(ValueError, match="unsupported JWT algorithm"):
        pqjwt.verify_jwt(bad_alg_token, b"P" * MLDSA65.PUBLIC_KEY_SIZE)


def test_reserved_header_override_and_invalid_cnf_claim_are_rejected(pqjwt):
    claims = {"sub": "alice"}

    with pytest.raises(ValueError, match="must not override"):
        pqjwt.sign_jwt(
            claims,
            b"S" * MLDSA65.SECRET_KEY_SIZE,
            extra_headers={"alg": "WRONG"},
        )

    with pytest.raises(ValueError, match="must only contain"):
        pqjwt.create_access_token(
            claims,
            b"S" * MLDSA65.SECRET_KEY_SIZE,
            cnf_claim={"wrong": "shape"},
        )


def test_extract_confirmation_claim_handles_missing_or_bad_tokens(pqjwt):
    assert pqjwt.extract_confirmation_claim("bad-token") is None
    token = pqjwt.create_access_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "api://resource",
            "exp": int(time.time()) + 600,
        },
        b"S" * MLDSA65.SECRET_KEY_SIZE,
        cnf_claim=build_access_token_binding_claim(
            type("Session", (), {"session_binding_id": b"\x01" * 32, "refresh_binding_id": b"\x02" * 32})()
        ),
    )
    assert pqjwt.extract_confirmation_claim(token)["kmt"] == "kemtls-exporter-v1"
