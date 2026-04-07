import hashlib
import time
from dataclasses import dataclass

from crypto.ml_dsa import MLDSA65
from oidc.auth_endpoints import AuthorizationEndpoint, InMemoryClientRegistry
from oidc.introspection_endpoints import IntrospectionEndpoint
from oidc.jwt_handler import PQJWT
from oidc.refresh_store import RefreshTokenStore
from oidc.token_endpoints import TokenEndpoint
from oidc.userinfo_endpoints import UserInfoEndpoint
from utils.encoding import base64url_encode


@dataclass
class DummySession:
    session_binding_id: bytes
    refresh_binding_id: bytes
    handshake_mode: str = "baseline"


ISSUER_PUBLIC_KEY, ISSUER_SECRET_KEY = MLDSA65.generate_keypair()


def _patch_signatures(monkeypatch):
    pass


def _pkce_challenge(verifier: str) -> str:
    return base64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())


def _build_stack():
    issuer_public_key = b"P" * MLDSA65.PUBLIC_KEY_SIZE
    registry = InMemoryClientRegistry(
        {"client123": {"redirect_uris": ["https://client.example/cb"]}}
    )
    auth = AuthorizationEndpoint(client_registry=registry)
    token_endpoint = TokenEndpoint(
        issuer_url="https://issuer.example",
        issuer_sk=ISSUER_SECRET_KEY,
        issuer_pk=ISSUER_PUBLIC_KEY,
        authorization_code_store=auth.code_store,
        refresh_token_store=RefreshTokenStore(),
        signing_kid="signing-key-1",
    )
    userinfo = UserInfoEndpoint(
        ISSUER_PUBLIC_KEY,
        issuer="https://issuer.example",
        audience="client123",
    )
    introspection = IntrospectionEndpoint(
        ISSUER_PUBLIC_KEY,
        issuer="https://issuer.example",
        audience="client123",
    )
    return auth, token_endpoint, userinfo, introspection


def _issue_tokens(auth, token_endpoint, *, verifier="verifier-123", session=None):
    session = session or DummySession(b"a" * 32, b"b" * 32)
    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid profile email",
        state="state123",
        nonce="nonce123",
        user_id="alice",
        code_challenge=_pkce_challenge(verifier),
    )
    return token_endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=session,
    )


def test_authorization_code_is_one_time_use(monkeypatch):
    _patch_signatures(monkeypatch)
    auth, token_endpoint, _, _ = _build_stack()
    verifier = "verifier-123"
    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state123",
        user_id="alice",
        code_challenge=_pkce_challenge(verifier),
    )

    first = token_endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=DummySession(b"a" * 32, b"b" * 32),
    )
    second = token_endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=DummySession(b"a" * 32, b"b" * 32),
    )

    assert "access_token" in first
    assert second["error"] == "invalid_grant"


def test_access_token_replay_is_rejected_on_new_session(monkeypatch):
    _patch_signatures(monkeypatch)
    auth, token_endpoint, userinfo, introspection = _build_stack()
    original_session = DummySession(b"a" * 32, b"b" * 32)
    tokens = _issue_tokens(auth, token_endpoint, session=original_session)

    payload, status = userinfo.handle_userinfo_request(
        tokens["access_token"],
        session=DummySession(b"z" * 32, b"b" * 32),
    )
    introspected = introspection.introspect(
        tokens["access_token"],
        session=DummySession(b"z" * 32, b"b" * 32, "pdk"),
    )

    assert status == 401
    assert payload["error"] == "binding_mismatch"
    assert introspected["active"] is False
    assert introspected["binding_status"] is False


def test_refresh_token_reuse_revokes_the_family(monkeypatch):
    _patch_signatures(monkeypatch)
    auth, token_endpoint, _, _ = _build_stack()
    tokens = _issue_tokens(auth, token_endpoint)

    refreshed = token_endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id="client123",
        refresh_token=tokens["refresh_token"],
        session=DummySession(b"c" * 32, b"b" * 32),
    )
    replay = token_endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id="client123",
        refresh_token=tokens["refresh_token"],
        session=DummySession(b"c" * 32, b"b" * 32),
    )
    stale_family_member = token_endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id="client123",
        refresh_token=refreshed["refresh_token"],
        session=DummySession(b"c" * 32, b"b" * 32),
    )

    assert "refresh_token" in refreshed
    assert replay["error"] == "invalid_grant"
    assert stale_family_member["error"] == "invalid_grant"


def test_tampered_and_expired_access_tokens_are_rejected(monkeypatch):
    _patch_signatures(monkeypatch)
    auth, token_endpoint, userinfo, introspection = _build_stack()
    tokens = _issue_tokens(auth, token_endpoint)

    parts = tokens["access_token"].split(".")
    tampered = ".".join([parts[0], parts[1], base64url_encode(b"\x00" * 32)])
    invalid_payload, invalid_status = userinfo.handle_userinfo_request(
        tampered,
        session=DummySession(b"a" * 32, b"b" * 32),
    )
    assert invalid_status == 401
    assert invalid_payload["error"] == "invalid_token"

    jwt = PQJWT()
    expired = jwt.create_access_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "client123",
            "client_id": "client123",
            "scope": "openid",
            "exp": int(time.time()) - 1,
        },
        ISSUER_SECRET_KEY,
        kid="signing-key-1",
        cnf_claim={"cnf": {"kmt": "kemtls-exporter-v1", "kbh": "x"}},
    )

    expired_info = introspection.introspect(expired)
    assert expired_info == {"active": False}


def test_wrong_audience_is_rejected_across_validation_surfaces(monkeypatch):
    _patch_signatures(monkeypatch)
    auth, token_endpoint, userinfo, introspection = _build_stack()
    tokens = _issue_tokens(auth, token_endpoint)

    wrong_audience_userinfo = UserInfoEndpoint(
        ISSUER_PUBLIC_KEY,
        issuer="https://issuer.example",
        audience="wrong-audience",
    )
    wrong_audience_introspection = IntrospectionEndpoint(
        ISSUER_PUBLIC_KEY,
        issuer="https://issuer.example",
        audience="wrong-audience",
    )

    payload, status = wrong_audience_userinfo.handle_userinfo_request(
        tokens["access_token"],
        session=DummySession(b"a" * 32, b"b" * 32),
    )
    introspected = wrong_audience_introspection.introspect(
        tokens["access_token"],
        session=DummySession(b"a" * 32, b"b" * 32),
    )

    assert status == 401
    assert payload["error"] == "invalid_token"
    assert introspected == {"active": False}
