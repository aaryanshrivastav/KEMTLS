"""Standalone smoke test for the current server app-factory layer."""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass


CURRENT_DIR = os.path.dirname(__file__)
SRC_DIR = os.path.dirname(CURRENT_DIR)
if sys.path and sys.path[0] == CURRENT_DIR:
    sys.path.pop(0)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from crypto.ml_dsa import MLDSA65
from servers.auth_server_app import create_auth_server_app
from servers.resource_server_app import create_resource_server_app
from utils.encoding import base64url_encode


@dataclass
class _Session:
    session_binding_id: bytes
    refresh_binding_id: bytes
    handshake_mode: str = "baseline"


def _pkce_challenge(verifier: str) -> str:
    return base64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run_sandbox() -> None:
    from oidc import jwt_handler as jwt_handler_module

    print("[sandbox] patching ML-DSA backend")
    original_sign = jwt_handler_module.MLDSA65.sign
    original_verify = jwt_handler_module.MLDSA65.verify
    jwt_handler_module.MLDSA65.sign = classmethod(
        lambda cls, _sk, message: hashlib.sha256(message).digest()
    )
    jwt_handler_module.MLDSA65.verify = classmethod(
        lambda cls, _pk, message, signature: signature == hashlib.sha256(message).digest()
    )

    try:
        auth_config = {
            "issuer": "https://issuer.example",
            "issuer_public_key": b"P" * MLDSA65.PUBLIC_KEY_SIZE,
            "issuer_secret_key": b"S" * MLDSA65.SECRET_KEY_SIZE,
            "signing_kid": "signing-key-1",
            "clients": {"client123": {"redirect_uris": ["https://client.example/cb"]}},
            "demo_user": "alice",
            "introspection_endpoint": "https://issuer.example/introspect",
        }
        resource_config = {
            "issuer": "https://issuer.example",
            "issuer_public_key": b"P" * MLDSA65.PUBLIC_KEY_SIZE,
            "resource_audience": "client123",
        }

        auth_app = create_auth_server_app(auth_config)
        resource_app = create_resource_server_app(resource_config)
        auth_client = auth_app.test_client()
        resource_client = resource_app.test_client()
        verifier = "server-sandbox-verifier"
        session = _Session(b"a" * 32, b"b" * 32)

        print("[auth] GET discovery")
        _assert(
            auth_client.get("/.well-known/openid-configuration").status_code == 200,
            "discovery failed",
        )

        print("[auth] GET authorize")
        auth_response = auth_client.get(
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
        _assert(auth_response.status_code == 200, "authorize failed")
        code = auth_response.get_json()["code"]

        print("[auth] POST token")
        token_response = auth_client.post(
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
        _assert(token_response.status_code == 200, "token issuance failed")
        access_token = token_response.get_json()["access_token"]

        print("[auth] POST introspect")
        introspect_response = auth_client.post(
            "/introspect",
            json={"token": access_token},
            environ_overrides={"kemtls.session": session},
        )
        _assert(introspect_response.get_json()["active"] is True, "introspection failed")

        print("[resource] GET userinfo")
        userinfo_response = resource_client.get(
            "/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            environ_overrides={"kemtls.session": session},
        )
        _assert(userinfo_response.status_code == 200, "userinfo failed")

        print("servers sandbox checks passed")
    finally:
        jwt_handler_module.MLDSA65.sign = original_sign
        jwt_handler_module.MLDSA65.verify = original_verify


if __name__ == "__main__":
    run_sandbox()
