from oidc.discovery import DiscoveryEndpoint


def test_discovery_metadata_contains_standard_and_extension_fields():
    discovery = DiscoveryEndpoint(
        "https://issuer.example/",
        introspection_endpoint="https://issuer.example/introspect",
        kemtls_modes_supported=["baseline", "pdk", "auto"],
    )

    config = discovery.get_configuration()

    assert config["issuer"] == "https://issuer.example"
    assert config["authorization_endpoint"] == "https://issuer.example/authorize"
    assert config["token_endpoint"] == "https://issuer.example/token"
    assert config["jwks_uri"] == "https://issuer.example/jwks"
    assert config["grant_types_supported"] == ["authorization_code", "refresh_token"]
    assert config["id_token_signing_alg_values_supported"] == ["ML-DSA-65"]
    assert config["kemtls_session_binding_supported"] is True
    assert config["kemtls_modes_supported"] == ["baseline", "pdk", "auto"]
    assert config["introspection_endpoint"] == "https://issuer.example/introspect"


def test_discovery_allows_configured_endpoints():
    discovery = DiscoveryEndpoint(
        "https://issuer.example",
        authorization_endpoint="https://auth.example/authorize",
        token_endpoint="https://auth.example/token",
        userinfo_endpoint="https://api.example/userinfo",
        jwks_uri="https://keys.example/jwks.json",
        kemtls_session_binding_supported=False,
        scopes_supported=["openid"],
    )

    config = discovery.get_configuration()

    assert config["authorization_endpoint"] == "https://auth.example/authorize"
    assert config["token_endpoint"] == "https://auth.example/token"
    assert config["userinfo_endpoint"] == "https://api.example/userinfo"
    assert config["jwks_uri"] == "https://keys.example/jwks.json"
    assert config["kemtls_session_binding_supported"] is False
    assert config["scopes_supported"] == ["openid"]


def test_discovery_omits_optional_introspection_when_not_configured():
    discovery = DiscoveryEndpoint("https://issuer.example/")

    config = discovery.get_configuration()

    assert "introspection_endpoint" not in config
    assert config["issuer"] == "https://issuer.example"
