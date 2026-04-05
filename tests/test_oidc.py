import hashlib
import time
from dataclasses import dataclass

from crypto.ml_dsa import MLDSA65
from oidc.auth_endpoints import AuthorizationEndpoint, InMemoryClientRegistry
from oidc.discovery import DiscoveryEndpoint
from oidc.jwks import JWKSEndpoint
from oidc.jwt_handler import ACCESS_TOKEN_TYPE, ID_TOKEN_TYPE, PQJWT
from oidc.refresh_store import RefreshTokenStore
from oidc.token_endpoints import TokenEndpoint
from utils.encoding import base64url_encode


@dataclass
class DummySession:
    session_binding_id: bytes
    refresh_binding_id: bytes
    handshake_mode: str = "baseline"


from oidc.authorization import AuthorizationEndpoint
from oidc.token import TokenEndpoint
from oidc.jwt_handler import PQJWT
from utils.encoding import base64url_decode
from utils.helpers import get_timestamp
from crypto.ml_dsa import DilithiumSignature
def _patch_signatures(monkeypatch):
    monkeypatch.setattr(
        "oidc.jwt_handler.MLDSA65.sign",
        lambda _sk, message: hashlib.sha256(message).digest(),
    )
    monkeypatch.setattr(
        "oidc.jwt_handler.MLDSA65.verify",
        lambda _pk, message, signature: signature == hashlib.sha256(message).digest(),
    )


def _pkce_challenge(verifier: str) -> str:
    return base64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())


def _build_stack():
    issuer_public_key = b"P" * MLDSA65.PUBLIC_KEY_SIZE
    registry = InMemoryClientRegistry(
        {"client123": {"redirect_uris": ["https://client.example/cb"]}}
    )
    auth = AuthorizationEndpoint(client_registry=registry)
    token = TokenEndpoint(
        issuer_url="https://issuer.example",
        issuer_sk=b"issuer-secret-key",
        issuer_pk=issuer_public_key,
        authorization_code_store=auth.code_store,
        refresh_token_store=RefreshTokenStore(),
        signing_kid="signing-key-1",
    )
    jwks = JWKSEndpoint({"signing-key-1": issuer_public_key})
    discovery = DiscoveryEndpoint(
        "https://issuer.example",
        jwks_uri="https://issuer.example/jwks",
        introspection_endpoint="https://issuer.example/introspect",
    )
    return auth, token, jwks, discovery


def test_authorization_code_pkce_token_and_metadata_flow(monkeypatch):
    _patch_signatures(monkeypatch)
    auth, token_endpoint, jwks, discovery = _build_stack()
    verifier = "super-secret-verifier"

    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid profile email",
        state="state123",
        nonce="nonce123",
        user_id="alice",
        code_challenge=_pkce_challenge(verifier),
    )
    assert "code" in auth_result

    token_response = token_endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=DummySession(b"a" * 32, b"b" * 32),
    )
    assert set(token_response) >= {"id_token", "access_token", "refresh_token", "token_type"}

    jwt = PQJWT()
    id_header, id_claims = jwt.verify_jwt(
        token_response["id_token"],
        b"P" * MLDSA65.PUBLIC_KEY_SIZE,
        expected_type=ID_TOKEN_TYPE,
    )
    access_header, access_claims = jwt.verify_jwt(
        token_response["access_token"],
        b"P" * MLDSA65.PUBLIC_KEY_SIZE,
        expected_type=ACCESS_TOKEN_TYPE,
    )
    jwks_doc = jwks.get_jwks()
    config = discovery.get_configuration()

    assert id_claims["sub"] == "alice"
    assert access_claims["client_id"] == "client123"
    assert id_header["kid"] == access_header["kid"] == "signing-key-1"
    assert any(key["kid"] == id_header["kid"] for key in jwks_doc["keys"])
    assert config["jwks_uri"] == "https://issuer.example/jwks"
    assert config["introspection_endpoint"] == "https://issuer.example/introspect"


def test_refresh_rotation_preserves_clean_oidc_shape(monkeypatch):
    _patch_signatures(monkeypatch)
    auth, token_endpoint, _, _ = _build_stack()
    verifier = "super-secret-verifier"

    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state123",
        user_id="alice",
        code_challenge=_pkce_challenge(verifier),
    )
    initial = token_endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=DummySession(b"a" * 32, b"b" * 32),
    )

    refreshed = token_endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id="client123",
        refresh_token=initial["refresh_token"],
        session=DummySession(b"c" * 32, b"b" * 32),
    )

    assert refreshed["token_type"] == "Bearer"
    assert "id_token" not in refreshed
    assert "access_token" in refreshed
    assert "refresh_token" in refreshed
    assert refreshed["scope"] == "openid"


def test_discovery_advertises_the_supported_oidc_and_kemtls_capabilities():
    _, _, _, discovery = _build_stack()
    config = discovery.get_configuration()

    assert config["response_types_supported"] == ["code"]
    assert config["grant_types_supported"] == ["authorization_code", "refresh_token"]
    assert config["kemtls_session_binding_supported"] is True
    assert config["kemtls_modes_supported"] == ["baseline", "pdk", "auto"]


def test_token_lifetimes_are_forward_moving(monkeypatch):
    _patch_signatures(monkeypatch)
    auth, token_endpoint, _, _ = _build_stack()
    verifier = "super-secret-verifier"

    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state123",
        user_id="alice",
        code_challenge=_pkce_challenge(verifier),
    )
    response = token_endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=DummySession(b"a" * 32, b"b" * 32),
    )

    claims = PQJWT().validate_access_token(
        response["access_token"],
        b"P" * MLDSA65.PUBLIC_KEY_SIZE,
        issuer="https://issuer.example",
        audience="client123",
    )
    assert claims["exp"] > claims["iat"]
    assert claims["exp"] > int(time.time())
