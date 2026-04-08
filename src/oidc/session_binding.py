"""Helpers for binding OIDC artifacts to a KEMTLS session."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional
from rust_ext import hashing as rust_hashing

from crypto.ml_dsa import MLDSA65
from utils.encoding import base64url_encode
from utils.encoding import base64url_decode
from utils.serialization import serialize_message


BINDING_METHOD = "kemtls-exporter-v1"
POP_BINDING_METHOD = "kemtls-pop-v1"
HEADER_PUBLIC_KEY = "X-KEMTLS-Binding-Public-Key"
HEADER_SIGNATURE = "X-KEMTLS-Binding-Signature"


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


def build_access_token_pop_claim(public_key: bytes) -> Dict[str, Dict[str, Any]]:
    """Bind an access token to a client-held ML-DSA verification key."""
    return {
        "cnf": {
            "kmt": POP_BINDING_METHOD,
            "jwk": MLDSA65.public_key_to_jwk(public_key),
        }
    }


def build_binding_proof_message(session, method: str, path: str) -> bytes:
    """Create the deterministic message a client signs to prove binding possession."""
    binding_id = _get_session_bytes(session, "session_binding_id")
    normalized_method = str(method or "").upper() or "GET"
    normalized_path = str(path or "").strip() or "/"
    return serialize_message(
        {
            "context": POP_BINDING_METHOD,
            "method": normalized_method,
            "path": normalized_path,
            "session_binding_id": base64url_encode(binding_id),
        }
    )


def build_binding_proof_headers(
    session,
    public_key: bytes,
    secret_key: bytes,
    *,
    method: str,
    path: str,
) -> Dict[str, str]:
    """Build request headers that prove possession of the client binding key."""
    message = build_binding_proof_message(session, method, path)
    signature = MLDSA65.sign(secret_key, message)
    return {
        HEADER_PUBLIC_KEY: base64url_encode(public_key),
        HEADER_SIGNATURE: base64url_encode(signature),
    }


def extract_binding_proof_from_headers(headers: Any) -> Optional[Dict[str, bytes]]:
    """Parse PoP binding headers from a request-like header mapping."""
    if headers is None or not hasattr(headers, "get"):
        return None

    public_key_encoded = headers.get(HEADER_PUBLIC_KEY)
    signature_encoded = headers.get(HEADER_SIGNATURE)
    if not isinstance(public_key_encoded, str) or not isinstance(signature_encoded, str):
        return None

    try:
        return {
            "public_key": base64url_decode(public_key_encoded),
            "signature": base64url_decode(signature_encoded),
        }
    except Exception:
        return None


def verify_binding_proof(
    session,
    binding_proof: Optional[Dict[str, Any]],
    *,
    method: str,
    path: str,
) -> Optional[bytes]:
    """Verify a presented PoP binding proof and return the proven public key."""
    if not isinstance(binding_proof, dict):
        return None

    public_key = binding_proof.get("public_key")
    signature = binding_proof.get("signature")
    if not isinstance(public_key, bytes) or not isinstance(signature, bytes):
        return None

    try:
        message = build_binding_proof_message(session, method, path)
    except ValueError:
        return None

    if MLDSA65.verify(public_key, message, signature):
        return public_key
    return None


def verify_access_token_binding_claim(
    claim: Dict[str, Any],
    session,
    *,
    binding_proof: Optional[Dict[str, Any]] = None,
    method: str = "GET",
    path: str = "/userinfo",
) -> bool:
    """Verify that an access token confirmation claim matches the active session."""
    if not isinstance(claim, dict):
        return False

    cnf = claim.get("cnf")
    if not isinstance(cnf, dict):
        return False

    binding_method = cnf.get("kmt")
    if binding_method == POP_BINDING_METHOD:
        jwk = cnf.get("jwk")
        if not isinstance(jwk, dict):
            return False
        try:
            expected_public_key = MLDSA65.jwk_to_public_key(jwk)
        except Exception:
            return False
        presented_public_key = verify_binding_proof(
            session,
            binding_proof,
            method=method,
            path=path,
        )
        return presented_public_key == expected_public_key
    if binding_method != BINDING_METHOD:
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
    "POP_BINDING_METHOD",
    "HEADER_PUBLIC_KEY",
    "HEADER_SIGNATURE",
    "build_access_token_binding_claim",
    "build_access_token_pop_claim",
    "build_binding_proof_headers",
    "build_binding_proof_message",
    "extract_binding_proof_from_headers",
    "build_refresh_binding_metadata",
    "verify_access_token_binding_claim",
    "verify_binding_proof",
    "verify_refresh_binding_metadata",
]
