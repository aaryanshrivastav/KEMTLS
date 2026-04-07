from dataclasses import dataclass
import hashlib

from crypto.ml_dsa import MLDSA65
from oidc.auth_endpoints import AuthorizationEndpoint, InMemoryClientRegistry
from oidc.jwt_handler import PQJWT
from oidc.refresh_store import RefreshTokenStore
from oidc.session_binding import verify_access_token_binding_claim
from oidc.token_endpoints import TokenEndpoint
from utils.encoding import base64url_encode


@dataclass
class DummySession:
    session_binding_id: bytes
    refresh_binding_id: bytes
    handshake_mode: str = "baseline"


@dataclass
class BrokenSession:
    refresh_binding_id: bytes | None = None
    session_binding_id: bytes | None = None


ISSUER_PUBLIC_KEY, ISSUER_SECRET_KEY = MLDSA65.generate_keypair()


def _code_challenge(verifier: str) -> str:
    return base64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())


def _patch_signatures(monkeypatch):
    pass


def _build_endpoint():
    registry = InMemoryClientRegistry(
        {
            "client123": {
                "redirect_uris": ["https://client.example/cb"],
            }
        }
    )
    auth = AuthorizationEndpoint(client_registry=registry)
    endpoint = TokenEndpoint(
        issuer_url="https://issuer.example",
        issuer_sk=ISSUER_SECRET_KEY,
        issuer_pk=ISSUER_PUBLIC_KEY,
        authorization_code_store=auth.code_store,
        refresh_token_store=RefreshTokenStore(),
    )
    return auth, endpoint


def test_authorization_code_exchange_success(monkeypatch):
    _patch_signatures(monkeypatch)
    auth, endpoint = _build_endpoint()
    verifier = "very-secret-verifier"
    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid profile email",
        state="state123",
        nonce="nonce123",
        user_id="alice",
        code_challenge=_code_challenge(verifier),
    )

    session = DummySession(b"a" * 32, b"b" * 32)
    response = endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=session,
    )

    assert "id_token" in response
    assert "access_token" in response
    assert "refresh_token" in response

    jwt = PQJWT()
    id_claims = jwt.validate_id_token(
        response["id_token"],
        ISSUER_PUBLIC_KEY,
        issuer="https://issuer.example",
        audience="client123",
        nonce="nonce123",
    )
    assert id_claims["sub"] == "alice"
    access_claims = jwt.validate_access_token(
        response["access_token"],
        ISSUER_PUBLIC_KEY,
        issuer="https://issuer.example",
        audience="client123",
    )
    assert verify_access_token_binding_claim(access_claims, session) is True


def test_authorization_code_exchange_rejects_pkce_mismatch(monkeypatch):
    _patch_signatures(monkeypatch)
    auth, endpoint = _build_endpoint()
    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state123",
        user_id="alice",
        code_challenge=_code_challenge("correct-verifier"),
    )

    response = endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier="wrong-verifier",
        session=DummySession(b"a" * 32, b"b" * 32),
    )

    assert response["error"] == "invalid_grant"


def test_authorization_code_exchange_requires_session(monkeypatch):
    _patch_signatures(monkeypatch)
    auth, endpoint = _build_endpoint()
    verifier = "very-secret-verifier"
    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state123",
        user_id="alice",
        code_challenge=_code_challenge(verifier),
    )

    response = endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=None,
    )

    assert response["error"] == "invalid_request"


def test_authorization_code_exchange_requires_client_id_and_redirect_uri(monkeypatch):
    _patch_signatures(monkeypatch)
    auth, endpoint = _build_endpoint()
    verifier = "very-secret-verifier"
    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state123",
        user_id="alice",
        code_challenge=_code_challenge(verifier),
    )

    missing_client = endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id=None,
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=DummySession(b"a" * 32, b"b" * 32),
    )
    assert missing_client["error"] == "invalid_request"

    missing_redirect = endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="",
        code=auth_result["code"],
        code_verifier=verifier,
        session=DummySession(b"a" * 32, b"b" * 32),
    )
    assert missing_redirect["error"] == "invalid_request"


def test_authorization_code_exchange_rejects_code_data_pkce_bypass(monkeypatch):
    _patch_signatures(monkeypatch)
    _, endpoint = _build_endpoint()

    response = endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code_data={
            "client_id": "client123",
            "redirect_uri": "https://client.example/cb",
            "scope": "openid",
            "user_id": "alice",
            "code_challenge": _code_challenge("expected-verifier"),
            "code_challenge_method": "S256",
        },
        code_verifier=None,
        session=DummySession(b"a" * 32, b"b" * 32),
    )

    assert response["error"] == "invalid_request"


def test_authorization_code_exchange_rejects_malformed_code_data(monkeypatch):
    _patch_signatures(monkeypatch)
    _, endpoint = _build_endpoint()

    response = endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code_data={"client_id": "client123"},
        code_verifier="verifier",
        session=DummySession(b"a" * 32, b"b" * 32),
    )

    assert response["error"] == "invalid_request"


def test_authorization_code_exchange_fails_closed_on_missing_session_binding(monkeypatch):
    _patch_signatures(monkeypatch)
    auth, endpoint = _build_endpoint()
    verifier = "very-secret-verifier"
    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state123",
        user_id="alice",
        code_challenge=_code_challenge(verifier),
    )

    response = endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=BrokenSession(refresh_binding_id=b"b" * 32, session_binding_id=None),
    )

    assert response["error"] == "invalid_request"


def test_refresh_rotation_and_replay_detection(monkeypatch):
    _patch_signatures(monkeypatch)
    auth, endpoint = _build_endpoint()
    verifier = "very-secret-verifier"
    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state123",
        user_id="alice",
        code_challenge=_code_challenge(verifier),
    )

    first_session = DummySession(b"a" * 32, b"b" * 32)
    token_response = endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=first_session,
    )

    refresh_response = endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id="client123",
        refresh_token=token_response["refresh_token"],
        session=first_session,
    )
    assert "refresh_token" in refresh_response

    replay_response = endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id="client123",
        refresh_token=token_response["refresh_token"],
        session=first_session,
    )
    assert replay_response["error"] == "invalid_grant"

    family_revoked_response = endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id="client123",
        refresh_token=refresh_response["refresh_token"],
        session=first_session,
    )
    assert family_revoked_response["error"] == "invalid_grant"


def test_refresh_rejects_binding_mismatch(monkeypatch):
    _patch_signatures(monkeypatch)
    auth, endpoint = _build_endpoint()
    verifier = "very-secret-verifier"
    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state123",
        user_id="alice",
        code_challenge=_code_challenge(verifier),
    )

    token_response = endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=DummySession(b"a" * 32, b"b" * 32),
    )

    refresh_response = endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id="client123",
        refresh_token=token_response["refresh_token"],
        session=DummySession(b"a" * 32, b"z" * 32),
    )

    assert refresh_response["error"] == "invalid_grant"


def test_refresh_requires_client_id_and_session(monkeypatch):
    _patch_signatures(monkeypatch)
    auth, endpoint = _build_endpoint()
    verifier = "very-secret-verifier"
    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state123",
        user_id="alice",
        code_challenge=_code_challenge(verifier),
    )

    token_response = endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=DummySession(b"a" * 32, b"b" * 32),
    )

    missing_client = endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id=None,
        refresh_token=token_response["refresh_token"],
        session=DummySession(b"a" * 32, b"b" * 32),
    )
    assert missing_client["error"] == "invalid_request"

    missing_session = endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id="client123",
        refresh_token=token_response["refresh_token"],
        session=None,
    )
    assert missing_session["error"] == "invalid_request"


def test_refresh_rejects_unknown_expired_and_client_mismatched_tokens(monkeypatch):
    _patch_signatures(monkeypatch)
    auth, endpoint = _build_endpoint()
    verifier = "very-secret-verifier"
    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state123",
        user_id="alice",
        code_challenge=_code_challenge(verifier),
    )

    token_response = endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=DummySession(b"a" * 32, b"b" * 32),
    )

    unknown = endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id="client123",
        refresh_token="missing-token",
        session=DummySession(b"a" * 32, b"b" * 32),
    )
    assert unknown["error"] == "invalid_grant"

    client_mismatch = endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id="other-client",
        refresh_token=token_response["refresh_token"],
        session=DummySession(b"a" * 32, b"b" * 32),
    )
    assert client_mismatch["error"] == "invalid_grant"

    record = endpoint.refresh_token_store._lookup_token(token_response["refresh_token"])
    record.expires_at = 1
    expired = endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id="client123",
        refresh_token=token_response["refresh_token"],
        session=DummySession(b"a" * 32, b"b" * 32),
    )
    assert expired["error"] == "invalid_grant"


def test_refresh_fails_closed_on_missing_access_binding_material(monkeypatch):
    _patch_signatures(monkeypatch)
    auth, endpoint = _build_endpoint()
    verifier = "very-secret-verifier"
    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state123",
        user_id="alice",
        code_challenge=_code_challenge(verifier),
    )

    token_response = endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=DummySession(b"a" * 32, b"b" * 32),
    )

    response = endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id="client123",
        refresh_token=token_response["refresh_token"],
        session=BrokenSession(refresh_binding_id=b"b" * 32, session_binding_id=None),
    )

    assert response["error"] == "invalid_request"


def test_refresh_rejects_already_revoked_token(monkeypatch):
    _patch_signatures(monkeypatch)
    auth, endpoint = _build_endpoint()
    verifier = "very-secret-verifier"
    auth_result = auth.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state123",
        user_id="alice",
        code_challenge=_code_challenge(verifier),
    )

    token_response = endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id="client123",
        redirect_uri="https://client.example/cb",
        code=auth_result["code"],
        code_verifier=verifier,
        session=DummySession(b"a" * 32, b"b" * 32),
    )

    endpoint.refresh_token_store.revoke_family(token_response["refresh_token"])
    response = endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id="client123",
        refresh_token=token_response["refresh_token"],
        session=DummySession(b"a" * 32, b"b" * 32),
    )

    assert response["error"] == "invalid_grant"


def test_unsupported_grant_type_is_rejected(monkeypatch):
    _patch_signatures(monkeypatch)
    _, endpoint = _build_endpoint()

    response = endpoint.handle_token_request(grant_type="client_credentials")

    assert response["error"] == "unsupported_grant_type"
