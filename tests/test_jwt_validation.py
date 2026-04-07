import time

import pytest

from crypto.ml_dsa import MLDSA65
from oidc.jwt_handler import ACCESS_TOKEN_TYPE, ID_TOKEN_TYPE, PQJWT
from oidc.session_binding import build_access_token_binding_claim
from utils.encoding import base64url_encode
@pytest.fixture
def pqjwt():
    return PQJWT()


def test_id_and_access_tokens_remain_standard_shaped(pqjwt, mldsa_keypair):
    public_key, secret_key = mldsa_keypair
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
        secret_key,
    )
    access_token = pqjwt.create_access_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "api://resource",
            "exp": int(time.time()) + 600,
        },
        secret_key,
        cnf_claim=build_access_token_binding_claim(_Session()),
    )

    id_header, _ = pqjwt.verify_jwt(
        id_token,
        public_key,
        expected_type=ID_TOKEN_TYPE,
    )
    access_header, access_payload = pqjwt.verify_jwt(
        access_token,
        public_key,
        expected_type=ACCESS_TOKEN_TYPE,
    )

    assert id_token.count(".") == 2
    assert access_token.count(".") == 2
    assert id_header["typ"] == ID_TOKEN_TYPE
    assert access_header["typ"] == ACCESS_TOKEN_TYPE
    assert access_payload["cnf"]["kmt"] == "kemtls-exporter-v1"


def test_jwt_validation_rejects_wrong_claims_and_times(pqjwt, mldsa_keypair):
    public_key, secret_key = mldsa_keypair
    token = pqjwt.create_id_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "client123",
            "nonce": "nonce-1",
            "nbf": int(time.time()) - 10,
            "exp": int(time.time()) + 10,
        },
        secret_key,
    )

    with pytest.raises(ValueError, match="issuer mismatch"):
        pqjwt.validate_id_token(token, public_key, issuer="https://wrong")
    with pytest.raises(ValueError, match="audience mismatch"):
        pqjwt.validate_id_token(token, public_key, audience="wrong")
    with pytest.raises(ValueError, match="nonce mismatch"):
        pqjwt.validate_id_token(token, public_key, nonce="wrong")

    expired = pqjwt.create_id_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "client123",
            "exp": int(time.time()) - 1,
        },
        secret_key,
    )
    future = pqjwt.create_id_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "client123",
            "nbf": int(time.time()) + 600,
            "exp": int(time.time()) + 1200,
        },
        secret_key,
    )

    with pytest.raises(ValueError, match="token expired"):
        pqjwt.validate_id_token(expired, public_key)
    with pytest.raises(ValueError, match="not yet valid"):
        pqjwt.validate_id_token(future, public_key)


def test_jwt_validation_rejects_bad_format_alg_signature_and_cnf(pqjwt, mldsa_keypair):
    public_key, secret_key = mldsa_keypair
    with pytest.raises(ValueError, match="invalid JWT format"):
        pqjwt.verify_jwt("bad-token", public_key)

    token = pqjwt.create_id_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "client123",
            "exp": int(time.time()) + 600,
        },
        secret_key,
    )
    header_b64, payload_b64, signature_b64 = token.split(".")

    with pytest.raises(ValueError, match="unexpected JWT type"):
        pqjwt.verify_jwt(token, public_key, expected_type=ACCESS_TOKEN_TYPE)

    bad_header = base64url_encode(b'{"alg":"WRONG","kid":"x","typ":"JWT"}')
    bad_alg_token = ".".join([bad_header, payload_b64, signature_b64])
    with pytest.raises(ValueError, match="unsupported JWT algorithm"):
        pqjwt.verify_jwt(bad_alg_token, public_key)

    bad_signature = ".".join(
        [header_b64, payload_b64, base64url_encode(b"\x00" * MLDSA65.SIGNATURE_SIZE)]
    )
    with pytest.raises(ValueError, match="invalid JWT signature"):
        pqjwt.verify_jwt(bad_signature, public_key)

    with pytest.raises(ValueError, match="must only contain"):
        pqjwt.create_access_token(
            {"sub": "alice"},
            secret_key,
            cnf_claim={"wrong": "shape"},
        )

    with pytest.raises(ValueError, match="must not override"):
        pqjwt.sign_jwt(
            {"sub": "alice"},
            secret_key,
            extra_headers={"alg": "WRONG"},
        )
