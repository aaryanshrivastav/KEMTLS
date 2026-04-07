"""Helpers for binding OIDC artifacts to a KEMTLS session."""

from __future__ import annotations

import hashlib
from typing import Any, Dict
from rust_ext import hashing as rust_hashing

from utils.encoding import base64url_encode


BINDING_METHOD = "kemtls-exporter-v1"


def build_access_token_binding_claim(session) -> Dict[str, Dict[str, str]]:
    """Build a standards-inspired confirmation claim for an access token."""
    binding_id = _get_session_bytes(session, "session_binding_id")
    return {
        "cnf": {
            "kmt": BINDING_METHOD,
            "kbh": base64url_encode(
                rust_hashing.sha256_digest(
                    binding_id,
                    fallback=_sha256_digest_python,
                )
            ),
        }
    }


def verify_access_token_binding_claim(claim: Dict[str, Any], session) -> bool:
    """Verify that an access token confirmation claim matches the active session."""
    if not isinstance(claim, dict):
        return False

    cnf = claim.get("cnf")
    if not isinstance(cnf, dict):
        return False
    if cnf.get("kmt") != BINDING_METHOD:
        return False

    try:
        expected = build_access_token_binding_claim(session)["cnf"]["kbh"]
    except ValueError:
        return False
    return cnf.get("kbh") == expected


def build_refresh_binding_metadata(session) -> Dict[str, str]:
    """Build server-side binding metadata for refresh token rotation policy."""
    binding_id = _get_session_bytes(session, "refresh_binding_id")
    return {
        "binding_method": BINDING_METHOD,
        "binding_hash": base64url_encode(
            rust_hashing.sha256_digest(
                binding_id,
                fallback=_sha256_digest_python,
            )
        ),
    }


def verify_refresh_binding_metadata(stored_meta: Dict[str, Any], session) -> bool:
    """Verify stored refresh-token binding metadata against the active session."""
    if not isinstance(stored_meta, dict):
        return False
    if stored_meta.get("binding_method") != BINDING_METHOD:
        return False

    try:
        expected = build_refresh_binding_metadata(session)["binding_hash"]
    except ValueError:
        return False
    return stored_meta.get("binding_hash") == expected


def _get_session_bytes(session, attribute: str) -> bytes:
    if session is None:
        raise ValueError("session is required for KEMTLS binding")

    value = getattr(session, attribute, None)
    if isinstance(value, bytes) and value:
        return value
    if isinstance(value, str) and value:
        return value.encode("utf-8")
    raise ValueError(f"session.{attribute} must be populated bytes or str")


def _sha256_digest_python(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


__all__ = [
    "BINDING_METHOD",
    "build_access_token_binding_claim",
    "build_refresh_binding_metadata",
    "verify_access_token_binding_claim",
    "verify_refresh_binding_metadata",
]
