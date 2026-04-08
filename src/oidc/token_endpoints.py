"""Token endpoint primitives for the updated OIDC architecture."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

from oidc.auth_endpoints import AuthorizationCodeRecord, InMemoryAuthorizationCodeStore
from oidc.claims import ClaimsProcessor
from oidc.jwt_handler import DEFAULT_KID, PQJWT
from oidc.refresh_store import RefreshTokenStore
from oidc.session_binding import (
    build_access_token_binding_claim,
    build_access_token_pop_claim,
    build_refresh_binding_metadata,
    verify_binding_proof,
    verify_refresh_binding_metadata,
)
from utils.encoding import base64url_encode
from utils.helpers import generate_random_string, get_timestamp


class TokenEndpoint:
    """Issues and refreshes tokens while preserving the standard OIDC flow shape."""

    def __init__(
        self,
        issuer_url: str,
        issuer_sk: bytes,
        issuer_pk: bytes,
        authorization_code_store: Optional[InMemoryAuthorizationCodeStore] = None,
        refresh_token_store: Optional[RefreshTokenStore] = None,
        claims_processor: Optional[ClaimsProcessor] = None,
        signing_kid: str = DEFAULT_KID,
        access_token_lifetime_seconds: int = 900,
        id_token_lifetime_seconds: int = 3600,
        refresh_token_lifetime_seconds: int = 604800,
    ):
        self.issuer_url = issuer_url
        self.issuer_sk = issuer_sk
        self.issuer_pk = issuer_pk
        self.authorization_code_store = (
            authorization_code_store or InMemoryAuthorizationCodeStore()
        )
        self.refresh_token_store = refresh_token_store or RefreshTokenStore()
        self.claims_processor = claims_processor or ClaimsProcessor()
        self.signing_kid = signing_kid
        self.access_token_lifetime_seconds = access_token_lifetime_seconds
        self.id_token_lifetime_seconds = id_token_lifetime_seconds
        self.refresh_token_lifetime_seconds = refresh_token_lifetime_seconds
        self.jwt_handler = PQJWT()

    def handle_token_request(
        self,
        grant_type: str,
        client_id: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        code: Optional[str] = None,
        code_verifier: Optional[str] = None,
        refresh_token: Optional[str] = None,
        session=None,
        code_data: Optional[Dict[str, Any]] = None,
        binding_proof: Optional[Dict[str, Any]] = None,
        collector: Optional[Any] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        if collector:
            collector.start_token_request()
            
        if grant_type == "authorization_code":
            res = self._handle_authorization_code_grant(
                client_id=client_id,
                redirect_uri=redirect_uri,
                code=code,
                code_verifier=code_verifier,
                session=session,
                code_data=code_data,
                binding_proof=binding_proof,
                collector=collector
            )
        elif grant_type == "refresh_token":
            res = self._handle_refresh_token_grant(
                client_id=client_id,
                refresh_token=refresh_token,
                session=session,
                collector=collector
            )
        else:
            res = {"error": "unsupported_grant_type"}
            
        if collector:
            collector.end_token_request()
            # If successful, we can optionally return the metrics here or caller handles it
            
        return res

    def _handle_authorization_code_grant(
        self,
        *,
        client_id: Optional[str],
        redirect_uri: Optional[str],
        code: Optional[str],
        code_verifier: Optional[str],
        session,
        code_data: Optional[Dict[str, Any]],
        binding_proof: Optional[Dict[str, Any]] = None,
        collector: Optional[Any] = None,
    ) -> Dict[str, Any]:
        if session is None:
            return {
                "error": "invalid_request",
                "error_description": "active KEMTLS session required",
            }
        if not isinstance(client_id, str) or not client_id:
            return {"error": "invalid_request", "error_description": "client_id is required"}
        if not isinstance(redirect_uri, str) or not redirect_uri:
            return {
                "error": "invalid_request",
                "error_description": "redirect_uri is required",
            }
        if not isinstance(code_verifier, str) or not code_verifier:
            return {
                "error": "invalid_request",
                "error_description": "code_verifier is required",
            }

        if code_data is not None:
            record_data = self._normalize_code_data(code_data)
            if record_data is None:
                return {
                    "error": "invalid_request",
                    "error_description": "code_data is malformed",
                }
        else:
            record = self._consume_authorization_code(code)
            if record is None:
                return {
                    "error": "invalid_grant",
                    "error_description": "authorization code invalid",
                }
            record_data = self._validate_authorization_code_record(
                record=record,
                client_id=client_id,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
            )
            if record_data is None:
                return {
                    "error": "invalid_grant",
                    "error_description": "authorization code validation failed",
                }

        if client_id is not None and record_data["client_id"] != client_id:
            return {"error": "invalid_grant", "error_description": "client mismatch"}
        if redirect_uri is not None and record_data["redirect_uri"] != redirect_uri:
            return {"error": "invalid_grant", "error_description": "redirect URI mismatch"}

        if not self._verify_pkce(
            record_data["code_challenge"],
            record_data["code_challenge_method"],
            code_verifier,
        ):
            return {"error": "invalid_grant", "error_description": "PKCE verification failed"}

        try:
            return self._issue_authorization_code_tokens(
                record_data,
                session,
                binding_proof=binding_proof,
                collector=collector,
            )
        except ValueError as exc:
            return {"error": "invalid_request", "error_description": str(exc)}

    def _handle_refresh_token_grant(
        self,
        *,
        client_id: Optional[str],
        refresh_token: Optional[str],
        session,
        collector: Optional[Any] = None,
    ) -> Dict[str, Any]:
        if session is None:
            return {
                "error": "invalid_request",
                "error_description": "active KEMTLS session required",
            }
        if not isinstance(client_id, str) or not client_id:
            return {"error": "invalid_request", "error_description": "client_id is required"}

        record = self.refresh_token_store._lookup_token(refresh_token)
        if record is None:
            return {"error": "invalid_grant", "error_description": "unknown refresh token"}
        if record.revoked:
            return {"error": "invalid_grant", "error_description": "refresh token revoked"}
        if get_timestamp() >= record.expires_at:
            record.revoked = True
            return {"error": "invalid_grant", "error_description": "refresh token expired"}
        if record.used_at is not None:
            self.refresh_token_store.revoke_family(refresh_token)
            return {"error": "invalid_grant", "error_description": "refresh token reuse detected"}
        if client_id is not None and record.client_id != client_id:
            return {"error": "invalid_grant", "error_description": "client mismatch"}
        if not verify_refresh_binding_metadata(record.binding_meta, session):
            return {
                "error": "invalid_grant",
                "error_description": "refresh token binding mismatch",
            }

        new_binding_meta = build_refresh_binding_metadata(session)
        new_refresh_expiry = get_timestamp() + self.refresh_token_lifetime_seconds
        new_refresh_token = self.refresh_token_store.rotate_token(
            refresh_token,
            new_binding_meta,
            new_refresh_expiry,
        )
        if new_refresh_token is None:
            return {
                "error": "invalid_grant",
                "error_description": "refresh token rotation failed",
            }

        access_claims = self._build_access_token_claims(
            subject=record.subject,
            client_id=record.client_id,
            scope="openid",
        )
        try:
            access_cnf_claim = build_access_token_binding_claim(session)
        except ValueError:
            return {
                "error": "invalid_request",
                "error_description": "session binding material is missing from the active KEMTLS session",
            }

        access_token = self.jwt_handler.create_access_token(
            access_claims,
            self.issuer_sk,
            kid=self.signing_kid,
            cnf_claim=access_cnf_claim,
            collector=collector
        )
        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "Bearer",
            "expires_in": self.access_token_lifetime_seconds,
            "scope": "openid",
        }

    def _issue_authorization_code_tokens(
        self,
        code_data: Dict[str, Any],
        session,
        *,
        binding_proof: Optional[Dict[str, Any]] = None,
        collector: Optional[Any] = None,
    ) -> Dict[str, Any]:
        scopes = code_data["scope"].split()
        issued_at = get_timestamp()

        id_claims = {
            "iss": self.issuer_url,
            "sub": code_data["user_id"],
            "aud": code_data["client_id"],
            "iat": issued_at,
            "exp": issued_at + self.id_token_lifetime_seconds,
        }
        if code_data.get("nonce"):
            id_claims["nonce"] = code_data["nonce"]
        id_claims.update(self.claims_processor.get_user_claims(code_data["user_id"], scopes))

        access_claims = self._build_access_token_claims(
            subject=code_data["user_id"],
            client_id=code_data["client_id"],
            scope=code_data["scope"],
        )

        id_token = self.jwt_handler.create_id_token(
            id_claims,
            self.issuer_sk,
            kid=self.signing_kid,
            collector=collector
        )
        if binding_proof is not None:
            public_key = verify_binding_proof(
                session,
                binding_proof,
                method="POST",
                path="/token",
            )
            if public_key is None:
                raise ValueError("binding proof verification failed for the active KEMTLS session")
            access_cnf_claim = build_access_token_pop_claim(public_key)
        else:
            try:
                access_cnf_claim = build_access_token_binding_claim(session)
            except ValueError as exc:
                raise ValueError(
                    "session binding material is missing from the active KEMTLS session"
                ) from exc

        try:
            refresh_binding_meta = build_refresh_binding_metadata(session)
        except ValueError as exc:
            raise ValueError(
                "session binding material is missing from the active KEMTLS session"
            ) from exc

        access_token = self.jwt_handler.create_access_token(
            access_claims,
            self.issuer_sk,
            kid=self.signing_kid,
            cnf_claim=access_cnf_claim,
            collector=collector
        )
        refresh_expiry = get_timestamp() + self.refresh_token_lifetime_seconds
        issued_refresh_token = self.refresh_token_store.issue_token(
            code_data["user_id"],
            code_data["client_id"],
            refresh_binding_meta,
            refresh_expiry,
        )
        return {
            "access_token": access_token,
            "id_token": id_token,
            "refresh_token": issued_refresh_token,
            "token_type": "Bearer",
            "expires_in": self.access_token_lifetime_seconds,
            "scope": code_data["scope"],
        }

    def _build_access_token_claims(
        self,
        *,
        subject: str,
        client_id: str,
        scope: str,
    ) -> Dict[str, Any]:
        issued_at = get_timestamp()
        return {
            "iss": self.issuer_url,
            "sub": subject,
            "aud": client_id,
            "client_id": client_id,
            "scope": scope,
            "iat": issued_at,
            "exp": issued_at + self.access_token_lifetime_seconds,
            "jti": generate_random_string(24),
        }

    def _consume_authorization_code(self, code: Optional[str]) -> Optional[AuthorizationCodeRecord]:
        if not isinstance(code, str) or not code:
            return None
        record = self.authorization_code_store.consume(code)
        if record is None:
            return None
        if get_timestamp() > record.expires_at:
            return None
        return record

    def _validate_authorization_code_record(
        self,
        *,
        record: AuthorizationCodeRecord,
        client_id: Optional[str],
        redirect_uri: Optional[str],
        code_verifier: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        if client_id is None or redirect_uri is None or code_verifier is None:
            return None
        if record.client_id != client_id or record.redirect_uri != redirect_uri:
            return None
        if not self._verify_pkce(record.code_challenge, record.code_challenge_method, code_verifier):
            return None
        return {
            "client_id": record.client_id,
            "redirect_uri": record.redirect_uri,
            "scope": record.scope,
            "user_id": record.user_id,
            "nonce": record.nonce,
            "code_challenge": record.code_challenge,
            "code_challenge_method": record.code_challenge_method,
            "issued_at": record.issued_at,
            "expires_at": record.expires_at,
        }

    def _verify_pkce(
        self,
        expected_challenge: str,
        method: str,
        code_verifier: str,
    ) -> bool:
        if method != "S256":
            return False
        if not isinstance(code_verifier, str) or not code_verifier:
            return False
        challenge = base64url_encode(hashlib.sha256(code_verifier.encode("ascii")).digest())
        return challenge == expected_challenge

    def _normalize_code_data(self, code_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(code_data, dict):
            return None

        required_fields = {
            "client_id",
            "redirect_uri",
            "scope",
            "user_id",
            "code_challenge",
            "code_challenge_method",
        }
        if not required_fields.issubset(code_data):
            return None

        normalized = {
            "client_id": code_data["client_id"],
            "redirect_uri": code_data["redirect_uri"],
            "scope": code_data["scope"],
            "user_id": code_data["user_id"],
            "nonce": code_data.get("nonce"),
            "code_challenge": code_data["code_challenge"],
            "code_challenge_method": code_data["code_challenge_method"],
            "issued_at": code_data.get("issued_at", get_timestamp()),
            "expires_at": code_data.get("expires_at", get_timestamp() + 600),
        }
        if not all(
            isinstance(normalized[field], str) and normalized[field]
            for field in (
                "client_id",
                "redirect_uri",
                "scope",
                "user_id",
                "code_challenge",
                "code_challenge_method",
            )
        ):
            return None
        return normalized


__all__ = ["TokenEndpoint"]
