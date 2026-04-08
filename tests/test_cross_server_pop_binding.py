import hashlib
from dataclasses import dataclass

from crypto.ml_dsa import MLDSA65
from oidc.session_binding import build_binding_proof_headers
from servers.auth_server_app import create_auth_server_app
from servers.resource_server_app import create_resource_server_app
from utils.encoding import base64url_encode


@dataclass
class DummySession:
    session_binding_id: bytes
    refresh_binding_id: bytes
    handshake_mode: str = "baseline"


def _expand(seed: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha256(seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:length])


def _patch_signatures(monkeypatch):
    counter = {"value": 0}

    def _generate_keypair(cls):
        counter["value"] += 1
        seed = f"ml-dsa-seed-{counter['value']}".encode("ascii")
        public_key = _expand(seed, cls.PUBLIC_KEY_SIZE)
        secret_key = public_key + _expand(seed + b"-sk", cls.SECRET_KEY_SIZE - cls.PUBLIC_KEY_SIZE)
        return public_key, secret_key

    def _sign(cls, secret_key: bytes, message: bytes) -> bytes:
        public_key = secret_key[: cls.PUBLIC_KEY_SIZE]
        return _expand(hashlib.sha256(public_key + message).digest(), cls.SIGNATURE_SIZE)

    def _verify(cls, public_key: bytes, message: bytes, signature: bytes) -> bool:
        expected = _expand(hashlib.sha256(public_key + message).digest(), cls.SIGNATURE_SIZE)
        return signature == expected

    monkeypatch.setattr(MLDSA65, "generate_keypair", classmethod(_generate_keypair))
    monkeypatch.setattr(MLDSA65, "sign", classmethod(_sign))
    monkeypatch.setattr(MLDSA65, "verify", classmethod(_verify))


def _challenge(verifier: str) -> str:
    return base64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())


def test_cross_server_access_uses_client_pop_key_not_issuer_session(monkeypatch):
    _patch_signatures(monkeypatch)
    issuer_public_key, issuer_secret_key = MLDSA65.generate_keypair()
    client_public_key, client_secret_key = MLDSA65.generate_keypair()

    auth_app = create_auth_server_app(
        {
            "issuer": "https://issuer.example",
            "issuer_public_key": issuer_public_key,
            "issuer_secret_key": issuer_secret_key,
            "clients": {"client123": {"redirect_uris": ["https://client.example/cb"]}},
            "demo_user": "alice",
            "introspection_endpoint": "https://issuer.example/introspect",
        }
    )
    resource_app = create_resource_server_app(
        {
            "issuer": "https://issuer.example",
            "issuer_public_key": issuer_public_key,
            "resource_audience": "client123",
        }
    )

    auth_client = auth_app.test_client()
    resource_client = resource_app.test_client()
    issuer_session = DummySession(b"a" * 32, b"b" * 32)
    resource_session = DummySession(b"z" * 32, b"y" * 32)
    verifier = "cross-server-verifier"

    auth_result = auth_client.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": "client123",
            "redirect_uri": "https://client.example/cb",
            "scope": "openid profile email",
            "state": "state-1",
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
        headers=build_binding_proof_headers(
            issuer_session,
            client_public_key,
            client_secret_key,
            method="POST",
            path="/token",
        ),
        environ_overrides={"kemtls.session": issuer_session},
    )
    assert token_result.status_code == 200
    access_token = token_result.get_json()["access_token"]

    userinfo = resource_client.get(
        "/userinfo",
        headers={
            "Authorization": f"Bearer {access_token}",
            **build_binding_proof_headers(
                resource_session,
                client_public_key,
                client_secret_key,
                method="GET",
                path="/userinfo",
            ),
        },
        environ_overrides={"kemtls.session": resource_session},
    )

    assert userinfo.status_code == 200
    assert userinfo.get_json()["sub"] == "alice"


def test_cross_server_access_rejects_stolen_token_without_client_key(monkeypatch):
    _patch_signatures(monkeypatch)
    issuer_public_key, issuer_secret_key = MLDSA65.generate_keypair()
    client_public_key, client_secret_key = MLDSA65.generate_keypair()
    attacker_public_key, attacker_secret_key = MLDSA65.generate_keypair()

    auth_app = create_auth_server_app(
        {
            "issuer": "https://issuer.example",
            "issuer_public_key": issuer_public_key,
            "issuer_secret_key": issuer_secret_key,
            "clients": {"client123": {"redirect_uris": ["https://client.example/cb"]}},
            "demo_user": "alice",
        }
    )
    resource_app = create_resource_server_app(
        {
            "issuer": "https://issuer.example",
            "issuer_public_key": issuer_public_key,
            "resource_audience": "client123",
        }
    )

    auth_client = auth_app.test_client()
    resource_client = resource_app.test_client()
    issuer_session = DummySession(b"a" * 32, b"b" * 32)
    resource_session = DummySession(b"z" * 32, b"y" * 32)
    verifier = "cross-server-verifier"

    auth_result = auth_client.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": "client123",
            "redirect_uri": "https://client.example/cb",
            "scope": "openid profile email",
            "state": "state-1",
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
        headers=build_binding_proof_headers(
            issuer_session,
            client_public_key,
            client_secret_key,
            method="POST",
            path="/token",
        ),
        environ_overrides={"kemtls.session": issuer_session},
    )
    access_token = token_result.get_json()["access_token"]

    replay = resource_client.get(
        "/userinfo",
        headers={
            "Authorization": f"Bearer {access_token}",
            **build_binding_proof_headers(
                resource_session,
                attacker_public_key,
                attacker_secret_key,
                method="GET",
                path="/userinfo",
            ),
        },
        environ_overrides={"kemtls.session": resource_session},
    )

    assert replay.status_code == 401
    assert replay.get_json()["error"] == "binding_mismatch"
