"""Authorization Code + PKCE endpoint primitives."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from utils.helpers import generate_random_string, get_timestamp


@dataclass
class AuthorizationCodeRecord:
    code: str
    client_id: str
    redirect_uri: str
    scope: str
    user_id: str
    nonce: Optional[str]
    code_challenge: str
    code_challenge_method: str
    issued_at: int
    expires_at: int


class InMemoryAuthorizationCodeStore:
    def __init__(self):
        self._records: Dict[str, AuthorizationCodeRecord] = {}

    def issue(self, record: AuthorizationCodeRecord) -> None:
        self._records[record.code] = record

    def consume(self, code: str) -> Optional[AuthorizationCodeRecord]:
        return self._records.pop(code, None)


class InMemoryClientRegistry:
    def __init__(self, clients: Optional[Dict[str, Dict[str, Any]]] = None):
        self._clients = clients or {}

    def get(self, client_id: str) -> Optional[Dict[str, Any]]:
        return self._clients.get(client_id)

    def is_valid_redirect_uri(self, client_id: str, redirect_uri: str) -> bool:
        client = self.get(client_id)
        if client is None:
            return False
        allowed_redirect_uris = client.get("redirect_uris", [])
        return redirect_uri in allowed_redirect_uris


class AuthorizationEndpoint:
    """Issues authorization codes for a standard Authorization Code + PKCE flow."""

    def __init__(
        self,
        client_registry: Optional[InMemoryClientRegistry] = None,
        code_store: Optional[InMemoryAuthorizationCodeStore] = None,
        code_lifetime_seconds: int = 600,
    ):
        self.client_registry = client_registry or InMemoryClientRegistry()
        self.code_store = code_store or InMemoryAuthorizationCodeStore()
        self.code_lifetime_seconds = code_lifetime_seconds

    def handle_authorize_request(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: str,
        nonce: Optional[str] = None,
        user_id: Optional[str] = None,
        response_type: str = "code",
        code_challenge: Optional[str] = None,
        code_challenge_method: str = "S256",
    ) -> Dict[str, Any]:
        if response_type != "code":
            return {"error": "unsupported_response_type"}
        if not client_id or not redirect_uri or not scope or not state:
            return {"error": "invalid_request"}
        if not code_challenge:
            return {"error": "invalid_request", "error_description": "PKCE is required"}
        if code_challenge_method != "S256":
            return {"error": "invalid_request", "error_description": "PKCE S256 is required"}

        client = self.client_registry.get(client_id)
        if client is None:
            return {"error": "unauthorized_client", "error_description": "unknown client"}
        if not self.client_registry.is_valid_redirect_uri(client_id, redirect_uri):
            return {"error": "invalid_request", "error_description": "redirect URI not allowed"}
        if user_id is None:
            return {"auth_required": True}

        issued_at = get_timestamp()
        record = AuthorizationCodeRecord(
            code=generate_random_string(32),
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            user_id=user_id,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            issued_at=issued_at,
            expires_at=issued_at + self.code_lifetime_seconds,
        )
        self.code_store.issue(record)
        return {"code": record.code, "state": state}

    def validate_code(
        self,
        code: str,
        client_id: str,
        redirect_uri: str,
    ) -> Optional[Dict[str, Any]]:
        record = self.code_store.consume(code)
        if record is None:
            return None
        if record.client_id != client_id or record.redirect_uri != redirect_uri:
            return None
        if get_timestamp() > record.expires_at:
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


__all__ = [
    "AuthorizationCodeRecord",
    "AuthorizationEndpoint",
    "InMemoryAuthorizationCodeStore",
    "InMemoryClientRegistry",
]
