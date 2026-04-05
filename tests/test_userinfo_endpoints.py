import hashlib
import time
from dataclasses import dataclass

from flask import Flask

from oidc.jwt_handler import PQJWT
from oidc.session_binding import build_access_token_binding_claim
from oidc.userinfo_endpoints import UserInfoEndpoint


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


def _make_access_token(session):
    jwt = PQJWT()
    return jwt.create_access_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "client123",
            "client_id": "client123",
            "scope": "openid profile email",
            "email_verified": True,
            "exp": int(time.time()) + 600,
        },
        b"issuer-secret-key",
        cnf_claim=build_access_token_binding_claim(session),
    )


def test_userinfo_succeeds_on_same_session(monkeypatch):
    _patch_signatures(monkeypatch)
    session = DummySession(b"a" * 32, b"b" * 32)
    endpoint = UserInfoEndpoint(
        b"issuer-public-key",
        issuer="https://issuer.example",
        audience="client123",
    )

    payload, status = endpoint.handle_userinfo_request(_make_access_token(session), session=session)

    assert status == 200
    assert payload["sub"] == "alice"
    assert payload["name"] == "Alice"
    assert payload["email"] == "alice@example.com"
    assert payload["email_verified"] is True


def test_userinfo_rejects_replay_on_new_session(monkeypatch):
    _patch_signatures(monkeypatch)
    original_session = DummySession(b"a" * 32, b"b" * 32)
    new_session = DummySession(b"z" * 32, b"b" * 32)
    endpoint = UserInfoEndpoint(
        b"issuer-public-key",
        issuer="https://issuer.example",
        audience="client123",
    )

    payload, status = endpoint.handle_userinfo_request(
        _make_access_token(original_session),
        session=new_session,
    )

    assert status == 401
    assert payload["error"] == "binding_mismatch"


def test_userinfo_missing_session_fails_closed(monkeypatch):
    _patch_signatures(monkeypatch)
    session = DummySession(b"a" * 32, b"b" * 32)
    endpoint = UserInfoEndpoint(
        b"issuer-public-key",
        issuer="https://issuer.example",
        audience="client123",
    )

    payload, status = endpoint.handle_userinfo_request(_make_access_token(session), session=None)

    assert status == 401
    assert payload["error"] == "missing_session_context"


def test_userinfo_registers_both_routes(monkeypatch):
    _patch_signatures(monkeypatch)
    session = DummySession(b"a" * 32, b"b" * 32)
    token = _make_access_token(session)
    app = Flask(__name__)
    endpoint = UserInfoEndpoint(
        b"issuer-public-key",
        issuer="https://issuer.example",
        audience="client123",
    )
    endpoint.register_routes(app, get_session=lambda: session)
    client = app.test_client()

    response_one = client.get("/userinfo", headers={"Authorization": f"Bearer {token}"})
    response_two = client.get("/api/userinfo", headers={"Authorization": f"Bearer {token}"})

    assert response_one.status_code == 200
    assert response_two.status_code == 200
    assert response_one.get_json()["sub"] == "alice"


def test_userinfo_route_rejects_missing_bearer(monkeypatch):
    _patch_signatures(monkeypatch)
    app = Flask(__name__)
    endpoint = UserInfoEndpoint(b"issuer-public-key")
    endpoint.register_routes(app, get_session=lambda: DummySession(b"a" * 32, b"b" * 32))

    response = app.test_client().get("/userinfo")

    assert response.status_code == 401
    assert response.get_json()["error"] == "invalid_token"


def test_userinfo_rejects_invalid_and_expired_tokens(monkeypatch):
    _patch_signatures(monkeypatch)
    endpoint = UserInfoEndpoint(
        b"issuer-public-key",
        issuer="https://issuer.example",
        audience="client123",
    )
    session = DummySession(b"a" * 32, b"b" * 32)

    invalid_payload, invalid_status = endpoint.handle_userinfo_request("bad-token", session=session)
    expired_token = PQJWT().create_access_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "client123",
            "client_id": "client123",
            "scope": "openid",
            "exp": int(time.time()) - 10,
        },
        b"issuer-secret-key",
        cnf_claim=build_access_token_binding_claim(session),
    )
    expired_payload, expired_status = endpoint.handle_userinfo_request(expired_token, session=session)

    assert invalid_status == 401
    assert invalid_payload["error"] == "invalid_token"
    assert expired_status == 401
    assert expired_payload["error"] == "invalid_token"


def test_userinfo_rejects_token_without_binding_claim(monkeypatch):
    _patch_signatures(monkeypatch)
    endpoint = UserInfoEndpoint(
        b"issuer-public-key",
        issuer="https://issuer.example",
        audience="client123",
    )
    session = DummySession(b"a" * 32, b"b" * 32)
    token = PQJWT().create_access_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "client123",
            "client_id": "client123",
            "scope": "openid",
            "exp": int(time.time()) + 600,
        },
        b"issuer-secret-key",
    )

    payload, status = endpoint.handle_userinfo_request(token, session=session)

    assert status == 401
    assert payload["error"] == "binding_mismatch"


def test_userinfo_route_resolves_session_from_environ(monkeypatch):
    _patch_signatures(monkeypatch)
    session = DummySession(b"a" * 32, b"b" * 32)
    token = _make_access_token(session)
    app = Flask(__name__)
    endpoint = UserInfoEndpoint(
        b"issuer-public-key",
        issuer="https://issuer.example",
        audience="client123",
    )
    endpoint.register_routes(app)

    response = app.test_client().get(
        "/userinfo",
        headers={"Authorization": f"Bearer {token}"},
        environ_overrides={"kemtls.session": session},
    )

    assert response.status_code == 200
    assert response.get_json()["sub"] == "alice"


def test_userinfo_route_fails_closed_without_session_resolution(monkeypatch):
    _patch_signatures(monkeypatch)
    session = DummySession(b"a" * 32, b"b" * 32)
    token = _make_access_token(session)
    app = Flask(__name__)
    endpoint = UserInfoEndpoint(
        b"issuer-public-key",
        issuer="https://issuer.example",
        audience="client123",
    )
    endpoint.register_routes(app)

    response = app.test_client().get(
        "/userinfo",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
    assert response.get_json()["error"] == "missing_session_context"
