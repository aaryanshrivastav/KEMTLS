import hashlib
from dataclasses import dataclass

from flask import Flask

from crypto.ml_dsa import MLDSA65
from oidc.auth_endpoints import AuthorizationEndpoint, InMemoryClientRegistry
from oidc.discovery import DiscoveryEndpoint
from oidc.introspection_endpoints import IntrospectionEndpoint
from oidc.jwks import JWKSEndpoint
from oidc.refresh_store import RefreshTokenStore
from oidc.token_endpoints import TokenEndpoint
from oidc.userinfo_endpoints import UserInfoEndpoint
from utils.encoding import base64url_encode


@dataclass
class DummySession:
    session_binding_id: bytes
    refresh_binding_id: bytes
    handshake_mode: str = "baseline"


def _patch_signatures(monkeypatch):
    pass


def _pkce_challenge(verifier: str) -> str:
    return base64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())


def _build_oidc_app():
    app = Flask(__name__)
    issuer_public_key, issuer_secret_key = MLDSA65.generate_keypair()
    registry = InMemoryClientRegistry(
        {"client123": {"redirect_uris": ["https://client.example/cb"]}}
    )
    auth = AuthorizationEndpoint(client_registry=registry)
    token = TokenEndpoint(
        issuer_url="https://issuer.example",
        issuer_sk=issuer_secret_key,
        issuer_pk=issuer_public_key,
        authorization_code_store=auth.code_store,
        refresh_token_store=RefreshTokenStore(),
        signing_kid="signing-key-1",
    )
    discovery = DiscoveryEndpoint(
        "https://issuer.example",
        introspection_endpoint="https://issuer.example/introspect",
    )
    jwks = JWKSEndpoint({"signing-key-1": issuer_public_key})
    introspection = IntrospectionEndpoint(
        issuer_public_key,
        issuer="https://issuer.example",
        audience="client123",
    )
    userinfo = UserInfoEndpoint(
        issuer_public_key,
        issuer="https://issuer.example",
        audience="client123",
    )
    return app, auth, token, discovery, jwks, introspection, userinfo


def test_end_to_end_oidc_flow_across_modules(monkeypatch):
    _, auth, token, discovery, jwks, introspection, userinfo = _build_oidc_app()
    verifier = "flow-verifier"
    session = DummySession(b"a" * 32, b"b" * 32)

    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid profile email",
        state="state123",
        nonce="nonce123",
        user_id="alice",
        code_challenge=_pkce_challenge(verifier),
    )
    token_response = token.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=session,
    )

    discovery_doc = discovery.get_configuration()
    jwks_doc = jwks.get_jwks()
    introspection_doc = introspection.introspect(
        token_response["access_token"],
        session=session,
    )
    userinfo_doc, status = userinfo.handle_userinfo_request(
        token_response["access_token"],
        session=session,
    )

    assert discovery_doc["issuer"] == "https://issuer.example"
    assert any(key["kid"] == "signing-key-1" for key in jwks_doc["keys"])
    assert introspection_doc["active"] is True
    assert introspection_doc["binding_status"] is True
    assert status == 200
    assert userinfo_doc["sub"] == "alice"
    assert userinfo_doc["email"] == "alice@example.com"


def test_route_level_integration_with_session_resolution(monkeypatch):
    app, auth, token, _, jwks, introspection, userinfo = _build_oidc_app()
    jwks.register_routes(app)
    introspection.register_routes(app)
    userinfo.register_routes(app)

    verifier = "flow-verifier"
    session = DummySession(b"a" * 32, b"b" * 32)
    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid profile",
        state="state123",
        user_id="alice",
        code_challenge=_pkce_challenge(verifier),
    )
    token_response = token.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=session,
    )

    client = app.test_client()
    jwks_response = client.get("/jwks")
    introspect_response = client.post(
        "/introspect",
        json={"token": token_response["access_token"]},
        environ_overrides={"kemtls.session": session},
    )
    userinfo_response = client.get(
        "/userinfo",
        headers={"Authorization": f"Bearer {token_response['access_token']}"},
        environ_overrides={"kemtls.session": session},
    )

    assert jwks_response.status_code == 200
    assert introspect_response.status_code == 200
    assert introspect_response.get_json()["active"] is True
    assert userinfo_response.status_code == 200
    assert userinfo_response.get_json()["sub"] == "alice"


def test_cross_module_fail_closed_behavior(monkeypatch):
    _, auth, token, _, _, introspection, userinfo = _build_oidc_app()
    verifier = "flow-verifier"
    session = DummySession(b"a" * 32, b"b" * 32)

    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state123",
        user_id="alice",
        code_challenge=_pkce_challenge(verifier),
    )
    token_response = token.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=session,
    )

    bad_introspection = introspection.introspect(
        token_response["access_token"],
        session=DummySession(b"z" * 32, b"b" * 32),
    )
    bad_userinfo, status = userinfo.handle_userinfo_request(
        token_response["access_token"],
        session=DummySession(b"z" * 32, b"b" * 32),
    )

    assert bad_introspection["active"] is False
    assert bad_introspection["binding_status"] is False
    assert status == 401
    assert bad_userinfo["error"] == "binding_mismatch"
