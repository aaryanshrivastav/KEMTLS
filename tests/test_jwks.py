import pytest
from flask import Flask

from crypto.ml_dsa import MLDSA65
from oidc.jwks import JWKSEndpoint


def test_jwks_publishes_single_key_with_matching_kid():
    endpoint = JWKSEndpoint({"signing-key-1": b"P" * MLDSA65.PUBLIC_KEY_SIZE})

    jwks = endpoint.get_jwks()

    assert len(jwks["keys"]) == 1
    assert jwks["keys"][0]["kid"] == "signing-key-1"
    assert jwks["keys"][0]["alg"] == MLDSA65.ALGORITHM


def test_jwks_supports_multiple_keys_for_rotation():
    endpoint = JWKSEndpoint(
        {
            "old-key": b"P" * MLDSA65.PUBLIC_KEY_SIZE,
            "new-key": b"Q" * MLDSA65.PUBLIC_KEY_SIZE,
        }
    )

    jwks = endpoint.get_jwks()

    assert {entry["kid"] for entry in jwks["keys"]} == {"old-key", "new-key"}
    assert endpoint.get_key("new-key") == b"Q" * MLDSA65.PUBLIC_KEY_SIZE


def test_jwks_rejects_invalid_key_inputs():
    endpoint = JWKSEndpoint()

    with pytest.raises(ValueError):
        endpoint.add_key("", b"P" * MLDSA65.PUBLIC_KEY_SIZE)
    with pytest.raises(ValueError):
        endpoint.add_key("bad", b"short")

    assert endpoint.get_key("") is None


def test_jwks_empty_set_is_valid():
    endpoint = JWKSEndpoint()

    assert endpoint.get_jwks() == {"keys": []}


def test_jwks_registers_route():
    app = Flask(__name__)
    endpoint = JWKSEndpoint({"signing-key-1": b"P" * MLDSA65.PUBLIC_KEY_SIZE})
    endpoint.register_routes(app)

    response = app.test_client().get("/jwks")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["keys"][0]["kid"] == "signing-key-1"
