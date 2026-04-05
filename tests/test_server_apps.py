import hashlib
from dataclasses import dataclass

from crypto.ml_dsa import MLDSA65
from servers.auth_server import AuthorizationServer
from servers.auth_server_app import create_auth_server_app
from servers.resource_server import ResourceServer
from servers.resource_server_app import create_resource_server_app
from utils.encoding import base64url_encode


@dataclass
class DummySession:
    session_binding_id: bytes
    refresh_binding_id: bytes
    handshake_mode: str = "baseline"


def _patch_signatures(monkeypatch):
    monkeypatch.setattr(
        "oidc.jwt_handler.MLDSA65.sign",
        lambda _sk, message: hashlib.sha256(message).digest(),
    )
    monkeypatch.setattr(
        "oidc.jwt_handler.MLDSA65.verify",
        lambda _pk, message, signature: signature == hashlib.sha256(message).digest(),
    )


def _patch_generate_keypair(monkeypatch):
    monkeypatch.setattr(
        "servers.auth_server.MLDSA65.generate_keypair",
        lambda: (b"P" * MLDSA65.PUBLIC_KEY_SIZE, b"S" * MLDSA65.SECRET_KEY_SIZE),
    )


def _pkce_challenge(verifier: str) -> str:
    return base64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())


def _build_auth_config():
    return {
        "issuer": "https://issuer.example",
        "issuer_public_key": b"P" * MLDSA65.PUBLIC_KEY_SIZE,
        "issuer_secret_key": b"S" * MLDSA65.SECRET_KEY_SIZE,
        "signing_kid": "signing-key-1",
        "clients": {"client123": {"redirect_uris": ["https://client.example/cb"]}},
        "demo_user": "alice",
        "introspection_endpoint": "https://issuer.example/introspect",
        "resource_audience": "client123",
    }


def test_auth_server_app_wires_discovery_jwks_authorize_token_and_introspect(monkeypatch):
    _patch_signatures(monkeypatch)
    app = create_auth_server_app(_build_auth_config())
    client = app.test_client()
    verifier = "server-verifier"

    discovery = client.get("/.well-known/openid-configuration")
    jwks = client.get("/jwks")
    auth = client.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": "client123",
            "redirect_uri": "https://client.example/cb",
            "scope": "openid profile",
            "state": "state123",
            "nonce": "nonce123",
            "code_challenge": _pkce_challenge(verifier),
            "code_challenge_method": "S256",
        },
    )

    assert discovery.status_code == 200
    assert jwks.status_code == 200
    assert auth.status_code == 200
    code = auth.get_json()["code"]

    session = DummySession(b"a" * 32, b"b" * 32)
    token = client.post(
        "/token",
        json={
            "grant_type": "authorization_code",
            "client_id": "client123",
            "redirect_uri": "https://client.example/cb",
            "code": code,
            "code_verifier": verifier,
        },
        environ_overrides={"kemtls.session": session},
    )
    assert token.status_code == 200
    access_token = token.get_json()["access_token"]

    introspect = client.post(
        "/introspect",
        json={"token": access_token},
        environ_overrides={"kemtls.session": session},
    )
    assert introspect.status_code == 200
    assert introspect.get_json()["active"] is True


def test_auth_server_app_authorize_errors_and_auth_required(monkeypatch):
    _patch_signatures(monkeypatch)
    config = _build_auth_config()
    config.pop("demo_user")
    app = create_auth_server_app(config)
    client = app.test_client()

    invalid = client.get("/authorize", query_string={"client_id": "", "redirect_uri": ""})
    unsupported = client.get(
        "/authorize",
        query_string={
            "response_type": "token",
            "client_id": "client123",
            "redirect_uri": "https://client.example/cb",
            "scope": "openid",
            "state": "state123",
            "code_challenge": _pkce_challenge("server-verifier"),
            "code_challenge_method": "S256",
        },
    )
    auth_required = client.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": "client123",
            "redirect_uri": "https://client.example/cb",
            "scope": "openid",
            "state": "state123",
            "code_challenge": _pkce_challenge("server-verifier"),
            "code_challenge_method": "S256",
        },
    )

    assert invalid.status_code == 400
    assert invalid.get_json()["error"] == "invalid_request"
    assert unsupported.status_code == 400
    assert unsupported.get_json()["error"] == "unsupported_response_type"
    assert auth_required.status_code == 200
    assert auth_required.get_json()["auth_required"] is True


def test_auth_server_app_token_endpoint_fails_closed_without_session(monkeypatch):
    _patch_signatures(monkeypatch)
    app = create_auth_server_app(_build_auth_config())
    client = app.test_client()
    verifier = "server-verifier"

    auth = client.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": "client123",
            "redirect_uri": "https://client.example/cb",
            "scope": "openid",
            "state": "state123",
            "code_challenge": _pkce_challenge(verifier),
            "code_challenge_method": "S256",
        },
    )
    code = auth.get_json()["code"]

    token = client.post(
        "/token",
        json={
            "grant_type": "authorization_code",
            "client_id": "client123",
            "redirect_uri": "https://client.example/cb",
            "code": code,
            "code_verifier": verifier,
        },
    )

    assert token.status_code == 400
    assert token.get_json()["error"] == "invalid_request"


def test_auth_server_app_token_supports_refresh_and_active_kemtls_session(monkeypatch):
    _patch_signatures(monkeypatch)
    app = create_auth_server_app(_build_auth_config())
    client = app.test_client()
    verifier = "server-verifier"

    auth = client.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": "client123",
            "redirect_uri": "https://client.example/cb",
            "scope": "openid",
            "state": "state123",
            "code_challenge": _pkce_challenge(verifier),
            "code_challenge_method": "S256",
        },
    )
    code = auth.get_json()["code"]

    initial = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "client123",
            "redirect_uri": "https://client.example/cb",
            "code": code,
            "code_verifier": verifier,
        },
        environ_overrides={"active_kemtls_session": DummySession(b"a" * 32, b"b" * 32)},
    )
    assert initial.status_code == 200

    refreshed = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": "client123",
            "refresh_token": initial.get_json()["refresh_token"],
        },
        environ_overrides={"active_kemtls_session": DummySession(b"c" * 32, b"b" * 32)},
    )
    assert refreshed.status_code == 200
    assert "access_token" in refreshed.get_json()
    assert "refresh_token" in refreshed.get_json()


def test_auth_server_app_introspection_handles_missing_and_mismatched_binding(monkeypatch):
    _patch_signatures(monkeypatch)
    app = create_auth_server_app(_build_auth_config())
    client = app.test_client()
    verifier = "server-verifier"
    session = DummySession(b"a" * 32, b"b" * 32)

    auth = client.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": "client123",
            "redirect_uri": "https://client.example/cb",
            "scope": "openid",
            "state": "state123",
            "code_challenge": _pkce_challenge(verifier),
            "code_challenge_method": "S256",
        },
    )
    code = auth.get_json()["code"]
    token = client.post(
        "/token",
        json={
            "grant_type": "authorization_code",
            "client_id": "client123",
            "redirect_uri": "https://client.example/cb",
            "code": code,
            "code_verifier": verifier,
        },
        environ_overrides={"kemtls.session": session},
    )
    access_token = token.get_json()["access_token"]

    missing = client.post("/introspect", json={})
    mismatch = client.post(
        "/introspect",
        json={"token": access_token},
        environ_overrides={"kemtls.session": DummySession(b"z" * 32, b"b" * 32)},
    )

    assert missing.status_code == 200
    assert missing.get_json() == {"active": False}
    assert mismatch.status_code == 200
    assert mismatch.get_json()["active"] is False
    assert mismatch.get_json()["binding_status"] is False


def test_resource_server_app_enforces_session_bound_userinfo(monkeypatch):
    _patch_signatures(monkeypatch)
    auth_app = create_auth_server_app(_build_auth_config())
    resource_app = create_resource_server_app(
        {
            "issuer": "https://issuer.example",
            "issuer_public_key": b"P" * MLDSA65.PUBLIC_KEY_SIZE,
            "resource_audience": "client123",
        }
    )
    auth_client = auth_app.test_client()
    rs_client = resource_app.test_client()
    verifier = "server-verifier"
    original_session = DummySession(b"a" * 32, b"b" * 32)

    auth = auth_client.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": "client123",
            "redirect_uri": "https://client.example/cb",
            "scope": "openid profile email",
            "state": "state123",
            "code_challenge": _pkce_challenge(verifier),
            "code_challenge_method": "S256",
        },
    )
    code = auth.get_json()["code"]
    token = auth_client.post(
        "/token",
        json={
            "grant_type": "authorization_code",
            "client_id": "client123",
            "redirect_uri": "https://client.example/cb",
            "code": code,
            "code_verifier": verifier,
        },
        environ_overrides={"kemtls.session": original_session},
    )
    access_token = token.get_json()["access_token"]

    good = rs_client.get(
        "/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        environ_overrides={"kemtls.session": original_session},
    )
    replay = rs_client.get(
        "/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        environ_overrides={"kemtls.session": DummySession(b"z" * 32, b"b" * 32)},
    )

    assert good.status_code == 200
    assert good.get_json()["sub"] == "alice"
    assert replay.status_code == 401
    assert replay.get_json()["error"] == "binding_mismatch"


def test_resource_server_app_rejects_missing_bearer_missing_session_and_invalid_token(monkeypatch):
    _patch_signatures(monkeypatch)
    app = create_resource_server_app(
        {
            "issuer": "https://issuer.example",
            "issuer_public_key": b"P" * MLDSA65.PUBLIC_KEY_SIZE,
            "resource_audience": "client123",
        }
    )
    client = app.test_client()

    missing_bearer = client.get("/userinfo")
    invalid_token = client.get(
        "/userinfo",
        headers={"Authorization": "Bearer bad-token"},
        environ_overrides={"kemtls.session": DummySession(b"a" * 32, b"b" * 32)},
    )
    missing_session = client.get(
        "/userinfo",
        headers={"Authorization": "Bearer bad-token.bad-token.bad-token"},
    )

    assert missing_bearer.status_code == 401
    assert missing_bearer.get_json()["error"] == "invalid_token"
    assert invalid_token.status_code == 401
    assert invalid_token.get_json()["error"] == "invalid_token"
    assert missing_session.status_code == 401
    assert missing_session.get_json()["error"] == "missing_session_context"


def test_resource_server_app_supports_api_userinfo_and_active_kemtls_session(monkeypatch):
    _patch_signatures(monkeypatch)
    auth_app = create_auth_server_app(_build_auth_config())
    resource_app = create_resource_server_app(
        {
            "issuer": "https://issuer.example",
            "issuer_public_key": b"P" * MLDSA65.PUBLIC_KEY_SIZE,
            "resource_audience": "client123",
        }
    )
    auth_client = auth_app.test_client()
    rs_client = resource_app.test_client()
    verifier = "server-verifier"
    session = DummySession(b"a" * 32, b"b" * 32)

    auth = auth_client.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": "client123",
            "redirect_uri": "https://client.example/cb",
            "scope": "openid profile email",
            "state": "state123",
            "code_challenge": _pkce_challenge(verifier),
            "code_challenge_method": "S256",
        },
    )
    code = auth.get_json()["code"]
    token = auth_client.post(
        "/token",
        json={
            "grant_type": "authorization_code",
            "client_id": "client123",
            "redirect_uri": "https://client.example/cb",
            "code": code,
            "code_verifier": verifier,
        },
        environ_overrides={"active_kemtls_session": session},
    )
    access_token = token.get_json()["access_token"]

    response = rs_client.get(
        "/api/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        environ_overrides={"active_kemtls_session": session},
    )

    assert response.status_code == 200
    assert response.get_json()["sub"] == "alice"


def test_app_factories_expose_expected_extensions(monkeypatch):
    _patch_signatures(monkeypatch)
    auth_app = create_auth_server_app(_build_auth_config())
    resource_app = create_resource_server_app(
        {
            "issuer": "https://issuer.example",
            "issuer_public_key": b"P" * MLDSA65.PUBLIC_KEY_SIZE,
            "resource_audience": "client123",
        }
    )

    assert {"auth_endpoint", "token_endpoint", "discovery_endpoint", "jwks_endpoint", "introspection_endpoint"} <= set(auth_app.extensions)
    assert "auth_server_stores" in auth_app.extensions
    assert "userinfo_endpoint" in resource_app.extensions


def test_compatibility_wrappers_create_working_apps(monkeypatch):
    _patch_signatures(monkeypatch)
    _patch_generate_keypair(monkeypatch)

    auth_server = AuthorizationServer("https://issuer.example")
    resource_server = ResourceServer(b"P" * MLDSA65.PUBLIC_KEY_SIZE)

    assert auth_server.app is not None
    assert resource_server.app is not None
    assert auth_server.auth_endpoint is auth_server.app.extensions["auth_endpoint"]
    assert auth_server.token_endpoint is auth_server.app.extensions["token_endpoint"]


def test_compatibility_wrappers_accept_config_overrides(monkeypatch):
    _patch_signatures(monkeypatch)
    _patch_generate_keypair(monkeypatch)

    auth_server = AuthorizationServer(
        "https://issuer.example",
        config={"demo_user": "bob", "clients": {"client123": {"redirect_uris": ["https://client.example/cb"]}}},
    )
    resource_server = ResourceServer(
        b"P" * MLDSA65.PUBLIC_KEY_SIZE,
        config={"issuer": "https://issuer.example", "resource_audience": "client123"},
    )

    assert auth_server.issuer_url == "https://issuer.example"
    assert resource_server.issuer_pk == b"P" * MLDSA65.PUBLIC_KEY_SIZE
