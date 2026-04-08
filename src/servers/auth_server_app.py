"""Authorization server Flask app factory for the updated architecture."""

from __future__ import annotations

from typing import Any, Dict, Optional

from flask import Flask, g, jsonify, request

from oidc.session_binding import extract_binding_proof_from_headers
from oidc.auth_endpoints import (
    AuthorizationEndpoint,
    InMemoryAuthorizationCodeStore,
    InMemoryClientRegistry,
)
from oidc.claims import ClaimsProcessor
from oidc.discovery import DiscoveryEndpoint
from oidc.introspection_endpoints import IntrospectionEndpoint
from oidc.jwks import JWKSEndpoint
from oidc.refresh_store import RefreshTokenStore
from oidc.token_endpoints import TokenEndpoint


def create_auth_server_app(
    config: Dict[str, Any],
    stores: Optional[Dict[str, Any]] = None,
) -> Flask:
    stores = stores or {}
    app = Flask(__name__)

    issuer = config["issuer"]
    issuer_pk = config["issuer_public_key"]
    issuer_sk = config["issuer_secret_key"]
    signing_kid = config.get("signing_kid", "signing-key-1")

    client_registry = stores.get("client_registry") or InMemoryClientRegistry(
        config.get("clients", {})
    )
    auth_code_store = stores.get("auth_code_store") or InMemoryAuthorizationCodeStore()
    refresh_token_store = stores.get("refresh_token_store") or RefreshTokenStore()
    claims_processor = stores.get("claims_processor") or ClaimsProcessor()

    auth_endpoint = AuthorizationEndpoint(
        client_registry=client_registry,
        code_store=auth_code_store,
        code_lifetime_seconds=config.get("authorization_code_lifetime_seconds", 600),
    )
    token_endpoint = TokenEndpoint(
        issuer_url=issuer,
        issuer_sk=issuer_sk,
        issuer_pk=issuer_pk,
        authorization_code_store=auth_code_store,
        refresh_token_store=refresh_token_store,
        claims_processor=claims_processor,
        signing_kid=signing_kid,
        access_token_lifetime_seconds=config.get("access_token_lifetime_seconds", 900),
        id_token_lifetime_seconds=config.get("id_token_lifetime_seconds", 3600),
        refresh_token_lifetime_seconds=config.get("refresh_token_lifetime_seconds", 604800),
    )
    discovery_endpoint = DiscoveryEndpoint(
        issuer,
        authorization_endpoint=config.get("authorization_endpoint"),
        token_endpoint=config.get("token_endpoint"),
        userinfo_endpoint=config.get("userinfo_endpoint"),
        jwks_uri=config.get("jwks_uri"),
        introspection_endpoint=config.get("introspection_endpoint"),
        kemtls_modes_supported=config.get("kemtls_modes_supported"),
        kemtls_session_binding_supported=config.get(
            "kemtls_session_binding_supported",
            True,
        ),
        scopes_supported=config.get("scopes_supported"),
    )
    jwks_endpoint = JWKSEndpoint({signing_kid: issuer_pk})
    introspection_endpoint = IntrospectionEndpoint(
        issuer_pk,
        issuer=issuer,
        audience=config.get("introspection_audience"),
    )

    app.extensions["auth_endpoint"] = auth_endpoint
    app.extensions["token_endpoint"] = token_endpoint
    app.extensions["discovery_endpoint"] = discovery_endpoint
    app.extensions["jwks_endpoint"] = jwks_endpoint
    app.extensions["introspection_endpoint"] = introspection_endpoint
    app.extensions["auth_server_stores"] = {
        "client_registry": client_registry,
        "auth_code_store": auth_code_store,
        "refresh_token_store": refresh_token_store,
    }

    def _resolve_session():
        session = request.environ.get("kemtls.session")
        if session is None:
            session = request.environ.get("active_kemtls_session")
        if session is None:
            session = getattr(g, "active_kemtls_session", None)
        return session

    @app.route("/.well-known/openid-configuration", methods=["GET"])
    def openid_configuration():
        return jsonify(discovery_endpoint.get_configuration())

    jwks_endpoint.register_routes(app)
    introspection_endpoint.register_routes(app, get_session=_resolve_session)

    @app.route("/authorize", methods=["GET"])
    def authorize():
        result = auth_endpoint.handle_authorize_request(
            client_id=request.args.get("client_id", ""),
            redirect_uri=request.args.get("redirect_uri", ""),
            scope=request.args.get("scope", ""),
            state=request.args.get("state", ""),
            nonce=request.args.get("nonce"),
            user_id=request.headers.get("X-Demo-User") or config.get("demo_user"),
            response_type=request.args.get("response_type", "code"),
            code_challenge=request.args.get("code_challenge"),
            code_challenge_method=request.args.get("code_challenge_method", "S256"),
        )
        status = 400 if "error" in result else 200
        return jsonify(result), status

    @app.route("/token", methods=["POST"])
    def token():
        payload = request.get_json(silent=True) or request.form or {}
        result = token_endpoint.handle_token_request(
            grant_type=payload.get("grant_type", ""),
            client_id=payload.get("client_id"),
            redirect_uri=payload.get("redirect_uri"),
            code=payload.get("code"),
            code_verifier=payload.get("code_verifier"),
            refresh_token=payload.get("refresh_token"),
            session=_resolve_session(),
            binding_proof=extract_binding_proof_from_headers(request.headers),
        )
        status = 400 if "error" in result else 200
        return jsonify(result), status

    return app


__all__ = ["create_auth_server_app"]
