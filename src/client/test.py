"""Standalone smoke test for the current client package."""

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

import client.oidc_client as oidc_client_module
from client.kemtls_http_client import KEMTLSHttpClient
from client.oidc_client import OIDCClient
from utils.encoding import base64url_encode


@dataclass
class DummySession:
    session_id: str
    handshake_mode: str
    session_binding_id: bytes | str
    trusted_key_id: str | None = None


class FakeTransportClient:
    def request(self, host, port, method, path, body=b"", **_kwargs):
        if method == "GET":
            raw = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: 16\r\n"
                b"\r\n"
                b'{"status":"ok"}'
            )
        else:
            raw = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: 2\r\n"
                b"\r\n"
                b"{}"
            )
        session = DummySession(
            session_id="sess-1",
            handshake_mode="baseline",
            session_binding_id="binding-1",
            trusted_key_id=None,
        )
        return raw, session


class FakeHTTPClient:
    def __init__(self):
        self.ca_pk = None
        self.pdk_store = None
        self.expected_identity = "issuer.example"
        self.mode = "auto"
        self.calls = []

    def post(self, url, headers=None, data=None, json_data=None):
        self.calls.append(("POST", url, headers, data, json_data))
        payload = data or json_data or {}
        if payload.get("grant_type") == "authorization_code":
            return {
                "status": 200,
                "body": {
                    "access_token": "access-token-1",
                    "refresh_token": "refresh-token-1",
                    "id_token": "id-token-1",
                },
                "kemtls_metadata": {
                    "mode": "baseline",
                    "session_id": "sess-1",
                    "session_binding_id": "binding-1",
                },
            }
        if payload.get("grant_type") == "refresh_token":
            return {
                "status": 200,
                "body": {
                    "access_token": "access-token-2",
                    "refresh_token": "refresh-token-2",
                },
                "kemtls_metadata": {
                    "mode": "pdk",
                    "session_id": "sess-2",
                    "session_binding_id": "binding-2",
                },
            }
        raise AssertionError(f"Unexpected POST payload: {payload}")

    def get(self, url, headers=None, params=None):
        self.calls.append(("GET", url, headers, params, None))
        return {
            "status": 200,
            "body": {"sub": "alice", "status": "ok"},
            "kemtls_metadata": {
                "mode": "baseline",
                "session_id": "sess-1",
                "session_binding_id": "binding-1",
            },
        }


def _pkce(verifier: str) -> str:
    return base64url_encode(hashlib.sha256(verifier.encode("utf-8")).digest())


def run_sandbox() -> None:
    print("[kemtls_http_client] parse raw HTTP response")
    http_client = KEMTLSHttpClient(expected_identity="issuer.example")
    http_client.client = FakeTransportClient()
    parsed = http_client.get("kemtls://issuer.example/status")
    assert parsed["status"] == 200
    assert parsed["body"]["status"] == "ok"
    assert parsed["kemtls_metadata"]["mode"] == "baseline"

    print("[oidc_client] start_auth generates PKCE")
    fake_http = FakeHTTPClient()
    oidc = OIDCClient(
        http_client=fake_http,
        client_id="client123",
        issuer_url="kemtls://issuer.example",
        redirect_uri="https://client.example/cb",
    )
    auth_url = oidc.start_auth()
    assert "code_challenge=" in auth_url
    assert oidc.code_verifier is not None
    assert oidc.code_challenge == _pkce(oidc.code_verifier)

    print("[oidc_client] exchange_code stores issued tokens")
    token_data = oidc.exchange_code("auth-code-1")
    assert token_data["access_token"] == "access-token-1"
    assert oidc.access_token == "access-token-1"
    assert oidc.refresh_token == "refresh-token-1"
    assert oidc.id_token == "id-token-1"
    assert oidc.telemetry["handshakes"][0]["mode"] == "baseline"

    print("[oidc_client] call_api uses bearer token")
    api_response = oidc.call_api("kemtls://issuer.example/userinfo")
    assert api_response["status"] == 200
    assert api_response["body"]["sub"] == "alice"
    get_call = fake_http.calls[-1]
    assert get_call[2]["Authorization"] == "Bearer access-token-1"

    print("[oidc_client] refresh rotates tokens")
    refreshed = oidc.refresh()
    assert refreshed["access_token"] == "access-token-2"
    assert oidc.refresh_token == "refresh-token-2"
    assert oidc.telemetry["refresh_events"][-1]["status"] == "success"

    print("[oidc_client] replay_attack creates a fresh client")
    oidc_client_module.KEMTLSHttpClient = lambda **_: FakeHTTPClient()
    replay_response = oidc.replay_attack("kemtls://issuer.example/userinfo")
    assert replay_response["status"] == 200

    print("client sandbox checks passed")


if __name__ == "__main__":
    run_sandbox()
