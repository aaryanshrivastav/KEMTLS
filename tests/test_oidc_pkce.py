import hashlib

from oidc.auth_endpoints import AuthorizationEndpoint, InMemoryAuthorizationCodeStore, InMemoryClientRegistry
from utils.encoding import base64url_encode


def _challenge(verifier: str) -> str:
    return base64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())


def test_pkce_authorization_code_flow_happy_path():
    endpoint = AuthorizationEndpoint(
        client_registry=InMemoryClientRegistry(
            {"client123": {"redirect_uris": ["https://client.example/cb"]}}
        )
    )

    result = endpoint.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid profile",
        state="state-1",
        nonce="nonce-1",
        user_id="alice",
        code_challenge=_challenge("verifier-1"),
        code_challenge_method="S256",
    )
    consumed = endpoint.validate_code(
        result["code"],
        client_id="client123",
        redirect_uri="https://client.example/cb",
    )

    assert "code" in result
    assert consumed["nonce"] == "nonce-1"
    assert consumed["code_challenge"] == _challenge("verifier-1")


def test_pkce_authorize_rejects_missing_or_wrong_inputs():
    endpoint = AuthorizationEndpoint(
        client_registry=InMemoryClientRegistry(
            {"client123": {"redirect_uris": ["https://client.example/cb"]}}
        )
    )

    missing_pkce = endpoint.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state-1",
        user_id="alice",
    )
    wrong_method = endpoint.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state-1",
        user_id="alice",
        code_challenge="challenge",
        code_challenge_method="plain",
    )
    wrong_response_type = endpoint.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state-1",
        user_id="alice",
        response_type="token",
        code_challenge="challenge",
        code_challenge_method="S256",
    )

    assert missing_pkce["error"] == "invalid_request"
    assert wrong_method["error"] == "invalid_request"
    assert wrong_response_type["error"] == "unsupported_response_type"


def test_pkce_authorize_rejects_unknown_client_redirect_and_reuse(monkeypatch):
    endpoint = AuthorizationEndpoint(
        client_registry=InMemoryClientRegistry(
            {"client123": {"redirect_uris": ["https://client.example/cb"]}}
        ),
        code_store=InMemoryAuthorizationCodeStore(),
        code_lifetime_seconds=1,
    )

    unknown_client = endpoint.handle_authorize_request(
        client_id="missing",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state-1",
        user_id="alice",
        code_challenge="challenge",
        code_challenge_method="S256",
    )
    wrong_redirect = endpoint.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://wrong.example/cb",
        scope="openid",
        state="state-1",
        user_id="alice",
        code_challenge="challenge",
        code_challenge_method="S256",
    )

    assert unknown_client["error"] == "unauthorized_client"
    assert wrong_redirect["error"] == "invalid_request"

    monkeypatch.setattr("oidc.auth_endpoints.generate_random_string", lambda _: "fixed-code")
    monkeypatch.setattr("oidc.auth_endpoints.get_timestamp", lambda: 1_000)
    issued = endpoint.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state-1",
        user_id="alice",
        code_challenge="challenge",
        code_challenge_method="S256",
    )
    first = endpoint.validate_code("fixed-code", "client123", "https://client.example/cb")
    second = endpoint.validate_code("fixed-code", "client123", "https://client.example/cb")

    assert first is not None
    assert second is None
    assert issued["code"] == "fixed-code"


def test_pkce_authorize_requires_user_authentication():
    endpoint = AuthorizationEndpoint(
        client_registry=InMemoryClientRegistry(
            {"client123": {"redirect_uris": ["https://client.example/cb"]}}
        )
    )

    result = endpoint.handle_authorize_request(
        client_id="client123",
        redirect_uri="https://client.example/cb",
        scope="openid",
        state="state-1",
        code_challenge="challenge",
        code_challenge_method="S256",
    )

    assert result == {"auth_required": True}
