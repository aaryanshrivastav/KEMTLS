"""Optional token introspection for observability and debugging."""

from __future__ import annotations

from typing import Any, Dict, Optional

from flask import g, jsonify, request

from oidc.jwt_handler import PQJWT
from oidc.session_binding import extract_binding_proof_from_headers
from oidc.session_binding import verify_access_token_binding_claim


class IntrospectionEndpoint:
    """Validates access tokens and reports selected claims plus binding state."""

    def __init__(
        self,
        issuer_pk: bytes,
        *,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        jwt_handler: Optional[PQJWT] = None,
    ):
        self.issuer_pk = issuer_pk
        self.issuer = issuer
        self.audience = audience
        self.jwt_handler = jwt_handler or PQJWT()

    def introspect(
        self,
        token: str,
        session=None,
        *,
        binding_proof: Optional[Dict[str, Any]] = None,
        method: str = "POST",
        path: str = "/introspect",
    ) -> Dict[str, Any]:
        if not isinstance(token, str) or not token:
            return {"active": False}

        try:
            claims = self.jwt_handler.validate_access_token(
                token,
                self.issuer_pk,
                issuer=self.issuer,
                audience=self.audience,
            )
        except Exception:
            return {"active": False}

        response: Dict[str, Any] = {
            "active": True,
            "sub": claims.get("sub"),
            "client_id": claims.get("client_id"),
            "scope": claims.get("scope"),
        }

        if session is not None:
            binding_ok = verify_access_token_binding_claim(
                claims,
                session,
                binding_proof=binding_proof,
                method=method,
                path=path,
            )
            response["binding_status"] = binding_ok
            response["active"] = bool(binding_ok)
            handshake_mode = getattr(session, "handshake_mode", None)
            if isinstance(handshake_mode, str) and handshake_mode:
                response["handshake_mode_seen"] = handshake_mode

        return response

    def register_routes(self, app, get_session=None) -> None:
        def _resolve_session():
            if callable(get_session):
                return get_session()
            session = request.environ.get("kemtls.session")
            if session is None:
                session = request.environ.get("active_kemtls_session")
            if session is None:
                session = getattr(g, "active_kemtls_session", None)
            return session

        @app.route("/introspect", methods=["POST"])
        def introspect_route():
            payload = request.get_json(silent=True) or request.form
            token = payload.get("token") if payload else None
            return jsonify(
                self.introspect(
                    token,
                    session=_resolve_session(),
                    binding_proof=extract_binding_proof_from_headers(request.headers),
                    method=request.method,
                    path=request.path,
                )
            )


__all__ = ["IntrospectionEndpoint"]
