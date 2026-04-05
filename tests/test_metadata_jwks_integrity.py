import hashlib
import time

from crypto.ml_dsa import MLDSA65
from oidc.discovery import DiscoveryEndpoint
from oidc.jwks import JWKSEndpoint
from oidc.jwt_handler import PQJWT


def _patch_signatures(monkeypatch):
    monkeypatch.setattr(
        "oidc.jwt_handler.MLDSA65.sign",
        lambda _sk, message: hashlib.sha256(message).digest(),
    )
    monkeypatch.setattr(
        "oidc.jwt_handler.MLDSA65.verify",
        lambda _pk, message, signature: signature == hashlib.sha256(message).digest(),
    )


def test_discovery_and_jwks_stay_consistent_with_token_headers(monkeypatch):
    _patch_signatures(monkeypatch)
    issuer_pk = b"P" * MLDSA65.PUBLIC_KEY_SIZE
    discovery = DiscoveryEndpoint(
        "https://issuer.example",
        jwks_uri="https://issuer.example/jwks",
        introspection_endpoint="https://issuer.example/introspect",
    )
    jwks = JWKSEndpoint({"signing-key-1": issuer_pk})
    token = PQJWT().create_id_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "client123",
            "exp": int(time.time()) + 600,
        },
        b"S" * MLDSA65.SECRET_KEY_SIZE,
        kid="signing-key-1",
    )

    header, _ = PQJWT().verify_jwt(
        token,
        issuer_pk,
        expected_type="JWT",
    )
    metadata = discovery.get_configuration()
    jwks_doc = jwks.get_jwks()

    assert metadata["jwks_uri"] == "https://issuer.example/jwks"
    assert metadata["id_token_signing_alg_values_supported"] == ["ML-DSA-65"]
    assert header["kid"] == "signing-key-1"
    assert any(key["kid"] == header["kid"] for key in jwks_doc["keys"])


def test_jwks_allows_rotation_without_custom_wrapping():
    jwks = JWKSEndpoint(
        {
            "old-key": b"P" * MLDSA65.PUBLIC_KEY_SIZE,
            "new-key": b"Q" * MLDSA65.PUBLIC_KEY_SIZE,
        }
    )

    document = jwks.get_jwks()

    assert set(document) == {"keys"}
    assert {entry["kid"] for entry in document["keys"]} == {"old-key", "new-key"}
