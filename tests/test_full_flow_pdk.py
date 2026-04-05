import hashlib
from dataclasses import dataclass

from crypto.ml_dsa import MLDSA65
from servers.auth_server_app import create_auth_server_app
from servers.resource_server_app import create_resource_server_app
from utils.encoding import base64url_encode


@dataclass
class DummySession:
    session_binding_id: bytes
    refresh_binding_id: bytes
    handshake_mode: str = "pdk"


def _patch_signatures(monkeypatch):
    monkeypatch.setattr(
        "oidc.jwt_handler.MLDSA65.sign",
        lambda _sk, message: hashlib.sha256(message).digest(),
    )
    monkeypatch.setattr(
        "oidc.jwt_handler.MLDSA65.verify",
        lambda _pk, message, signature: signature == hashlib.sha256(message).digest(),
    )


def _challenge(verifier: str) -> str:
    return base64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())


def test_full_pdk_flow_across_auth_and_resource_servers(monkeypatch):
    _patch_signatures(monkeypatch)
    auth_app = create_auth_server_app(
        {
            "issuer": "https://issuer.example",
            "issuer_public_key": b"P" * MLDSA65.PUBLIC_KEY_SIZE,
            "issuer_secret_key": b"S" * MLDSA65.SECRET_KEY_SIZE,
            "clients": {"client123": {"redirect_uris": ["https://client.example/cb"]}},
            "demo_user": "alice",
            "introspection_endpoint": "https://issuer.example/introspect",
            "kemtls_modes_supported": ["pdk", "auto"],
        }
    )
    resource_app = create_resource_server_app(
        {
            "issuer": "https://issuer.example",
            "issuer_public_key": b"P" * MLDSA65.PUBLIC_KEY_SIZE,
            "resource_audience": "client123",
        }
    )

    auth_client = auth_app.test_client()
    resource_client = resource_app.test_client()
    session = DummySession(b"p" * 32, b"r" * 32)
    verifier = "pdk-verifier"

    auth_result = auth_client.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": "client123",
            "redirect_uri": "https://client.example/cb",
            "scope": "openid profile email",
            "state": "state-1",
            "nonce": "nonce-1",
            "code_challenge": _challenge(verifier),
            "code_challenge_method": "S256",
        },
    )
    code = auth_result.get_json()["code"]

    token_result = auth_client.post(
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
    tokens = token_result.get_json()

    introspection = auth_client.post(
        "/introspect",
        json={"token": tokens["access_token"]},
        environ_overrides={"kemtls.session": session},
    )
    userinfo = resource_client.get(
        "/api/userinfo",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
        environ_overrides={"kemtls.session": session},
    )

    assert token_result.status_code == 200
    assert introspection.get_json()["active"] is True
    assert introspection.get_json()["handshake_mode_seen"] == "pdk"
    assert userinfo.status_code == 200
    assert userinfo.get_json()["sub"] == "alice"
