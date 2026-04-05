from oidc.auth_endpoints import (
    AuthorizationEndpoint,
    InMemoryAuthorizationCodeStore,
    InMemoryClientRegistry,
)


def test_authorization_code_flow_requires_pkce_and_stores_code():
    registry = InMemoryClientRegistry(
        {
            "client-123": {
                "redirect_uris": ["https://client.example/callback"],
            }
        }
    )
    store = InMemoryAuthorizationCodeStore()
    endpoint = AuthorizationEndpoint(client_registry=registry, code_store=store)

    result = endpoint.handle_authorize_request(
        client_id="client-123",
        redirect_uri="https://client.example/callback",
        scope="openid profile",
        state="state-123",
        nonce="nonce-123",
        user_id="alice",
        code_challenge="abc123",
        code_challenge_method="S256",
    )

    assert "code" in result
    consumed = endpoint.validate_code(
        result["code"],
        client_id="client-123",
        redirect_uri="https://client.example/callback",
    )
    assert consumed is not None
    assert consumed["code_challenge"] == "abc123"


def test_authorization_request_rejects_missing_pkce():
    endpoint = AuthorizationEndpoint()

    result = endpoint.handle_authorize_request(
        client_id="client-123",
        redirect_uri="https://client.example/callback",
        scope="openid",
        state="state-123",
        user_id="alice",
    )

    assert result["error"] == "invalid_request"


def test_authorization_request_requires_user_authentication():
    endpoint = AuthorizationEndpoint(
        client_registry=InMemoryClientRegistry(
            {"client-123": {"redirect_uris": ["https://client.example/callback"]}}
        )
    )

    result = endpoint.handle_authorize_request(
        client_id="client-123",
        redirect_uri="https://client.example/callback",
        scope="openid",
        state="state-123",
        code_challenge="challenge",
        code_challenge_method="S256",
    )

    assert result == {"auth_required": True}


def test_unknown_client_is_rejected():
    endpoint = AuthorizationEndpoint(
        client_registry=InMemoryClientRegistry(
            {"known-client": {"redirect_uris": ["https://client.example/callback"]}}
        )
    )

    result = endpoint.handle_authorize_request(
        client_id="client-123",
        redirect_uri="https://client.example/callback",
        scope="openid",
        state="state-123",
        user_id="alice",
        code_challenge="challenge",
        code_challenge_method="S256",
    )

    assert result["error"] == "unauthorized_client"


def test_invalid_redirect_uri_and_pkce_method_are_rejected():
    endpoint = AuthorizationEndpoint(
        client_registry=InMemoryClientRegistry(
            {"client-123": {"redirect_uris": ["https://client.example/callback"]}}
        )
    )

    redirect_result = endpoint.handle_authorize_request(
        client_id="client-123",
        redirect_uri="https://wrong.example/callback",
        scope="openid",
        state="state-123",
        user_id="alice",
        code_challenge="challenge",
        code_challenge_method="S256",
    )
    pkce_result = endpoint.handle_authorize_request(
        client_id="client-123",
        redirect_uri="https://client.example/callback",
        scope="openid",
        state="state-123",
        user_id="alice",
        code_challenge="challenge",
        code_challenge_method="plain",
    )

    assert redirect_result["error"] == "invalid_request"
    assert pkce_result["error"] == "invalid_request"


def test_unsupported_response_type_and_expired_or_reused_code_fail(monkeypatch):
    registry = InMemoryClientRegistry(
        {"client-123": {"redirect_uris": ["https://client.example/callback"]}}
    )
    endpoint = AuthorizationEndpoint(client_registry=registry, code_lifetime_seconds=1)

    wrong_response = endpoint.handle_authorize_request(
        client_id="client-123",
        redirect_uri="https://client.example/callback",
        scope="openid",
        state="state-123",
        response_type="token",
        user_id="alice",
        code_challenge="challenge",
        code_challenge_method="S256",
    )
    assert wrong_response["error"] == "unsupported_response_type"

    result = endpoint.handle_authorize_request(
        client_id="client-123",
        redirect_uri="https://client.example/callback",
        scope="openid",
        state="state-123",
        user_id="alice",
        code_challenge="challenge",
        code_challenge_method="S256",
    )

    consumed_once = endpoint.validate_code(
        result["code"],
        client_id="client-123",
        redirect_uri="https://client.example/callback",
    )
    consumed_twice = endpoint.validate_code(
        result["code"],
        client_id="client-123",
        redirect_uri="https://client.example/callback",
    )

    assert consumed_once is not None
    assert consumed_twice is None

    result = endpoint.handle_authorize_request(
        client_id="client-123",
        redirect_uri="https://client.example/callback",
        scope="openid",
        state="state-123",
        user_id="alice",
        code_challenge="challenge",
        code_challenge_method="S256",
    )

    monkeypatch.setattr("oidc.auth_endpoints.get_timestamp", lambda: 10_000)
    expiring_endpoint = AuthorizationEndpoint(
        client_registry=registry,
        code_store=InMemoryAuthorizationCodeStore(),
        code_lifetime_seconds=1,
    )
    monkeypatch.setattr("oidc.auth_endpoints.generate_random_string", lambda _: "fixed-code")
    issued = expiring_endpoint.handle_authorize_request(
        client_id="client-123",
        redirect_uri="https://client.example/callback",
        scope="openid",
        state="state-123",
        user_id="alice",
        code_challenge="challenge",
        code_challenge_method="S256",
    )
    monkeypatch.setattr("oidc.auth_endpoints.get_timestamp", lambda: 10_005)
    expired = expiring_endpoint.validate_code(
        issued["code"],
        client_id="client-123",
        redirect_uri="https://client.example/callback",
    )

    assert expired is None
