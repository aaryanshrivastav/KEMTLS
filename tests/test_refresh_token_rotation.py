import hashlib
from dataclasses import dataclass

from crypto.ml_dsa import MLDSA65
from oidc.auth_endpoints import AuthorizationEndpoint, InMemoryClientRegistry
from oidc.refresh_store import RefreshTokenStore
from oidc.session_binding import build_refresh_binding_metadata
from oidc.token_endpoints import TokenEndpoint
from utils.encoding import base64url_encode


@dataclass
class DummySession:
    session_binding_id: bytes
    refresh_binding_id: bytes
    handshake_mode: str = "baseline"


def _patch_signatures(monkeypatch):
    pass


def _challenge(verifier: str) -> str:
    return base64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())


def _build_endpoint():
    issuer_pk, issuer_sk = MLDSA65.generate_keypair()
    auth = AuthorizationEndpoint(
        client_registry=InMemoryClientRegistry(
            {"client123": {"redirect_uris": ["https://client.example/cb"]}}
        )
    )
    token = TokenEndpoint(
        issuer_url="https://issuer.example",
        issuer_sk=issuer_sk,
        issuer_pk=issuer_pk,
        authorization_code_store=auth.code_store,
        refresh_token_store=RefreshTokenStore(),
    )
    return auth, token


def test_refresh_store_hashes_tokens_and_detects_reuse():
    store = RefreshTokenStore()
    token = store.issue_token(
        "alice",
        "client123",
        build_refresh_binding_metadata(DummySession(b"a" * 32, b"b" * 32)),
        2_000_000_000,
    )

    assert token not in store._records
    first = store.consume_token(token)
    second = store.consume_token(token)

    assert first is not None
    assert second is None
    assert first.revoked is True


def test_refresh_token_rotation_and_replay_failure(monkeypatch):
    auth, token_endpoint = _build_endpoint()
    verifier = "verifier-1"
    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid profile",
        state="state-1",
        user_id="alice",
        code_challenge=_challenge(verifier),
    )

    issued = token_endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=DummySession(b"a" * 32, b"b" * 32),
    )
    rotated = token_endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id="client123",
        refresh_token=issued["refresh_token"],
        session=DummySession(b"c" * 32, b"b" * 32),
    )
    replay = token_endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id="client123",
        refresh_token=issued["refresh_token"],
        session=DummySession(b"c" * 32, b"b" * 32),
    )
    stale_family = token_endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id="client123",
        refresh_token=rotated["refresh_token"],
        session=DummySession(b"c" * 32, b"b" * 32),
    )

    assert "refresh_token" in rotated
    assert replay["error"] == "invalid_grant"
    assert stale_family["error"] == "invalid_grant"


def test_refresh_token_rotation_rejects_binding_mismatch(monkeypatch):
    auth, token_endpoint = _build_endpoint()
    verifier = "verifier-1"
    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state-1",
        user_id="alice",
        code_challenge=_challenge(verifier),
    )

    issued = token_endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=DummySession(b"a" * 32, b"b" * 32),
    )
    mismatched = token_endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id="client123",
        refresh_token=issued["refresh_token"],
        session=DummySession(b"a" * 32, b"z" * 32),
    )

    assert mismatched["error"] == "invalid_grant"
