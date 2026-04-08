"""Session-bound userinfo handlers for the resource server side."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from flask import g, jsonify, request

from oidc.claims import ClaimsProcessor
from oidc.jwt_handler import PQJWT
from oidc.session_binding import extract_binding_proof_from_headers
from oidc.session_binding import verify_access_token_binding_claim


class UserInfoEndpoint:
    """Validates access tokens locally and enforces active KEMTLS session binding."""

    def __init__(
        self,
        issuer_pk: bytes,
        *,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        claims_processor: Optional[ClaimsProcessor] = None,
        jwt_handler: Optional[PQJWT] = None,
    ):
        self.issuer_pk = issuer_pk
        self.issuer = issuer
        self.audience = audience
        self.claims_processor = claims_processor or ClaimsProcessor()
        self.jwt_handler = jwt_handler or PQJWT()

    def handle_userinfo_request(
        self,
        access_token: str,
        session=None,
        *,
        binding_proof: Optional[Dict[str, Any]] = None,
        method: str = "GET",
        path: str = "/userinfo",
        collector: Optional[Any] = None,
    ) -> Tuple[Dict[str, Any], int]:
        if collector:
            collector.start_userinfo_request()
            
        if not isinstance(access_token, str) or not access_token:
            if collector:
                collector.end_userinfo_request()
            return {"error": "invalid_token"}, 401
        if session is None:
            if collector:
                collector.end_userinfo_request()
            return {"error": "missing_session_context"}, 401

        try:
            claims = self.jwt_handler.validate_access_token(
                access_token,
                self.issuer_pk,
                issuer=self.issuer,
                audience=self.audience,
                collector=collector
            )
        except Exception:
            if collector:
                collector.end_userinfo_request()
            return {"error": "invalid_token"}, 401
            
        import time
        start_binding_ns = time.perf_counter_ns()
        binding_valid = verify_access_token_binding_claim(
            claims,
            session,
            binding_proof=binding_proof,
            method=method,
            path=path,
        )
        if collector:
            collector.t_binding_verify_ns = time.perf_counter_ns() - start_binding_ns

        if not binding_valid:
            # Security-critical: never allow any fallback path to override
            # session-binding mismatch for a cryptographically valid token.
            if collector:
                collector.end_userinfo_request()
            return {"error": "binding_mismatch"}, 401

        scopes = str(claims.get("scope", "")).split()
        response = self.claims_processor.get_user_claims(str(claims["sub"]), scopes)
        if "email_verified" in claims:
            response["email_verified"] = claims["email_verified"]
            
        if collector:
            collector.end_userinfo_request()
            
        return response, 200

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

        def _extract_bearer_token() -> Optional[str]:
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return None
            return auth_header[7:]

        @app.route("/userinfo", methods=["GET"])
        @app.route("/api/userinfo", methods=["GET"])
        def userinfo_route():
            token = _extract_bearer_token()
            if token is None:
                return jsonify({"error": "invalid_token"}), 401

            response, status = self.handle_userinfo_request(
                token,
                session=_resolve_session(),
                binding_proof=extract_binding_proof_from_headers(request.headers),
                method=request.method,
                path=request.path,
            )
            return jsonify(response), status


__all__ = ["UserInfoEndpoint"]
