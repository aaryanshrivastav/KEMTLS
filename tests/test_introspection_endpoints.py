import hashlib
import time
from dataclasses import dataclass

from crypto.ml_dsa import MLDSA65
from flask import Flask

from oidc.introspection_endpoints import IntrospectionEndpoint
from oidc.jwt_handler import PQJWT
from oidc.session_binding import build_access_token_binding_claim


@dataclass
class DummySession:
    session_binding_id: bytes
    refresh_binding_id: bytes
    handshake_mode: str = "baseline"


ISSUER_PUBLIC_KEY, ISSUER_SECRET_KEY = MLDSA65.generate_keypair()


def _patch_signatures(monkeypatch):
    pass


def _make_access_token():
    jwt = PQJWT()
    session = DummySession(b"a" * 32, b"b" * 32)
    token = jwt.create_access_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "client123",
            "client_id": "client123",
            "scope": "openid profile",
            "exp": int(time.time()) + 600,
        },
        ISSUER_SECRET_KEY,
        cnf_claim=build_access_token_binding_claim(session),
    )
    return token, session


def test_introspection_reports_active_token(monkeypatch):
    _patch_signatures(monkeypatch)
    token, _ = _make_access_token()
    endpoint = IntrospectionEndpoint(
        ISSUER_PUBLIC_KEY,
        issuer="https://issuer.example",
        audience="client123",
    )

    result = endpoint.introspect(token)

    assert result["active"] is True
    assert result["sub"] == "alice"
    assert result["client_id"] == "client123"
    assert result["scope"] == "openid profile"


def test_introspection_reports_binding_status_when_session_is_supplied(monkeypatch):
    _patch_signatures(monkeypatch)
    token, session = _make_access_token()
    endpoint = IntrospectionEndpoint(
        ISSUER_PUBLIC_KEY,
        issuer="https://issuer.example",
        audience="client123",
    )

    good = endpoint.introspect(token, session=session)
    bad = endpoint.introspect(token, session=DummySession(b"x" * 32, b"b" * 32, "pdk"))

    assert good["active"] is True
    assert good["binding_status"] is True
    assert good["handshake_mode_seen"] == "baseline"
    assert bad["active"] is False
    assert bad["binding_status"] is False
    assert bad["handshake_mode_seen"] == "pdk"


def test_introspection_invalid_token_is_inactive(monkeypatch):
    _patch_signatures(monkeypatch)
    endpoint = IntrospectionEndpoint(ISSUER_PUBLIC_KEY)

    assert endpoint.introspect("bad-token") == {"active": False}


def test_introspection_expired_token_is_inactive(monkeypatch):
    _patch_signatures(monkeypatch)
    jwt = PQJWT()
    session = DummySession(b"a" * 32, b"b" * 32)
    token = jwt.create_access_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "client123",
            "client_id": "client123",
            "scope": "openid",
            "exp": int(time.time()) - 10,
        },
        ISSUER_SECRET_KEY,
        cnf_claim=build_access_token_binding_claim(session),
    )
    endpoint = IntrospectionEndpoint(
        ISSUER_PUBLIC_KEY,
        issuer="https://issuer.example",
        audience="client123",
    )

    assert endpoint.introspect(token) == {"active": False}


def test_introspection_registers_route(monkeypatch):
    _patch_signatures(monkeypatch)
    token, session = _make_access_token()
    app = Flask(__name__)
    endpoint = IntrospectionEndpoint(
        ISSUER_PUBLIC_KEY,
        issuer="https://issuer.example",
        audience="client123",
    )
    endpoint.register_routes(app, get_session=lambda: session)

    response = app.test_client().post("/introspect", json={"token": token})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["active"] is True
    assert payload["binding_status"] is True


def test_introspection_route_supports_form_and_missing_token(monkeypatch):
    _patch_signatures(monkeypatch)
    token, _ = _make_access_token()
    app = Flask(__name__)
    endpoint = IntrospectionEndpoint(
        ISSUER_PUBLIC_KEY,
        issuer="https://issuer.example",
        audience="client123",
    )
    endpoint.register_routes(app)
    client = app.test_client()

    form_response = client.post("/introspect", data={"token": token})
    missing_response = client.post("/introspect", json={})

    assert form_response.status_code == 200
    assert form_response.get_json()["active"] is True
    assert missing_response.status_code == 200
    assert missing_response.get_json() == {"active": False}


def test_introspection_route_resolves_session_from_environ(monkeypatch):
    _patch_signatures(monkeypatch)
    token, session = _make_access_token()
    app = Flask(__name__)
    endpoint = IntrospectionEndpoint(
        ISSUER_PUBLIC_KEY,
        issuer="https://issuer.example",
        audience="client123",
    )
    endpoint.register_routes(app)

    response = app.test_client().post(
        "/introspect",
        json={"token": token},
        environ_overrides={"kemtls.session": session},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["active"] is True
    assert payload["binding_status"] is True
