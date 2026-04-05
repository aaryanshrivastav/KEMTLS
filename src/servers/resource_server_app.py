"""Resource server Flask app factory for the updated architecture."""

from __future__ import annotations

from typing import Any, Dict, Optional

from flask import Flask, g, request

from oidc.claims import ClaimsProcessor
from oidc.jwt_handler import PQJWT
from oidc.userinfo_endpoints import UserInfoEndpoint


def create_resource_server_app(
    config: Dict[str, Any],
    stores: Optional[Dict[str, Any]] = None,
) -> Flask:
    stores = stores or {}
    app = Flask(__name__)

    issuer_pk = config["issuer_public_key"]
    userinfo_endpoint = UserInfoEndpoint(
        issuer_pk,
        issuer=config.get("issuer"),
        audience=config.get("resource_audience"),
        claims_processor=stores.get("claims_processor") or ClaimsProcessor(),
        jwt_handler=stores.get("jwt_handler") or PQJWT(),
    )

    app.extensions["userinfo_endpoint"] = userinfo_endpoint

    def _resolve_session():
        session = request.environ.get("kemtls.session")
        if session is None:
            session = request.environ.get("active_kemtls_session")
        if session is None:
            session = getattr(g, "active_kemtls_session", None)
        return session

    userinfo_endpoint.register_routes(app, get_session=_resolve_session)
    return app


__all__ = ["create_resource_server_app"]
