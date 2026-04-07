"""Opaque refresh-token storage with rotation and replay detection."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, Optional
from rust_ext import hashing as rust_hashing

from utils.helpers import generate_random_string, get_timestamp


@dataclass
class RefreshTokenRecord:
    token_hash: str
    family_id: str
    subject: str
    client_id: str
    binding_meta: dict
    issued_at: int
    expires_at: int
    used_at: Optional[int] = None
    revoked: bool = False


class RefreshTokenStore:
    """Stores only hashed refresh tokens and enforces single-use rotation."""

    def __init__(self):
        self._records: Dict[str, RefreshTokenRecord] = {}

    def issue_token(
        self,
        subject: str,
        client_id: str,
        binding_meta: dict,
        expiry: int,
    ) -> str:
        self._validate_issue_inputs(subject, client_id, binding_meta, expiry)
        return self._issue_token(
            subject=subject,
            client_id=client_id,
            binding_meta=dict(binding_meta),
            expiry=expiry,
            family_id=generate_random_string(24),
        )

    def consume_token(self, token_value: str) -> Optional[RefreshTokenRecord]:
        record = self._lookup_token(token_value)
        if record is None:
            return None
        if record.revoked:
            return None
        if get_timestamp() >= record.expires_at:
            record.revoked = True
            return None
        if record.used_at is not None:
            self.revoke_family(token_value)
            return None

        record.used_at = get_timestamp()
        return record

    def rotate_token(
        self,
        old_token: str,
        new_binding_meta: dict,
        expiry: int,
    ) -> Optional[str]:
        if not isinstance(new_binding_meta, dict) or not new_binding_meta:
            raise ValueError("new_binding_meta must be a non-empty dictionary")
        if not isinstance(expiry, int):
            raise TypeError("expiry must be an integer timestamp")

        old_record = self.consume_token(old_token)
        if old_record is None:
            return None

        return self._issue_token(
            subject=old_record.subject,
            client_id=old_record.client_id,
            binding_meta=dict(new_binding_meta),
            expiry=expiry,
            family_id=old_record.family_id,
        )

    def revoke_family(self, token_value: str) -> bool:
        record = self._lookup_token(token_value)
        if record is None:
            return False

        for family_record in self._records.values():
            if family_record.family_id == record.family_id:
                family_record.revoked = True
        return True

    def _issue_token(
        self,
        *,
        subject: str,
        client_id: str,
        binding_meta: dict,
        expiry: int,
        family_id: str,
    ) -> str:
        token_value = generate_random_string(64)
        token_hash = self._hash_token(token_value)
        self._records[token_hash] = RefreshTokenRecord(
            token_hash=token_hash,
            family_id=family_id,
            subject=subject,
            client_id=client_id,
            binding_meta=binding_meta,
            issued_at=get_timestamp(),
            expires_at=expiry,
        )
        return token_value

    def _lookup_token(self, token_value: str) -> Optional[RefreshTokenRecord]:
        if not isinstance(token_value, str) or not token_value:
            return None
        return self._records.get(self._hash_token(token_value))

    def _hash_token(self, token_value: str) -> str:
        if not isinstance(token_value, str) or not token_value:
            raise ValueError("token_value must be a non-empty string")
        return rust_hashing.sha256_hex(token_value, fallback=_sha256_hex_python)

    def _validate_issue_inputs(
        self,
        subject: str,
        client_id: str,
        binding_meta: dict,
        expiry: int,
    ) -> None:
        if not isinstance(subject, str) or not subject:
            raise ValueError("subject must be a non-empty string")
        if not isinstance(client_id, str) or not client_id:
            raise ValueError("client_id must be a non-empty string")
        if not isinstance(binding_meta, dict) or not binding_meta:
            raise ValueError("binding_meta must be a non-empty dictionary")
        if not isinstance(expiry, int):
            raise TypeError("expiry must be an integer timestamp")
        if expiry <= get_timestamp():
            raise ValueError("expiry must be in the future")


__all__ = ["RefreshTokenRecord", "RefreshTokenStore"]


def _sha256_hex_python(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()
