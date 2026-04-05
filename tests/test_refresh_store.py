from types import SimpleNamespace

import pytest

from oidc.refresh_store import RefreshTokenStore
from oidc.session_binding import build_refresh_binding_metadata


def _session(suffix: bytes = b"a"):
    return SimpleNamespace(
        refresh_binding_id=suffix * 32,
        session_binding_id=b"s" * 32,
    )


def test_issue_stores_only_hashed_token():
    store = RefreshTokenStore()
    token = store.issue_token(
        "alice",
        "client123",
        build_refresh_binding_metadata(_session()),
        2_000_000_000,
    )

    assert token
    assert token not in store._records
    record = store._records[store._hash_token(token)]
    assert record.subject == "alice"
    assert record.client_id == "client123"


def test_consume_is_single_use_and_replay_revokes_family():
    store = RefreshTokenStore()
    token = store.issue_token(
        "alice",
        "client123",
        build_refresh_binding_metadata(_session()),
        2_000_000_000,
    )

    first = store.consume_token(token)
    assert first is not None
    assert first.used_at is not None

    second = store.consume_token(token)
    assert second is None
    assert first.revoked is True


def test_rotate_keeps_family_and_old_token_replay_revokes_new_token():
    store = RefreshTokenStore()
    original = store.issue_token(
        "alice",
        "client123",
        build_refresh_binding_metadata(_session(b"a")),
        2_000_000_000,
    )

    original_record = store._lookup_token(original)
    rotated = store.rotate_token(
        original,
        build_refresh_binding_metadata(_session(b"b")),
        2_000_000_100,
    )
    assert rotated is not None

    rotated_record = store._lookup_token(rotated)
    assert rotated_record is not None
    assert rotated_record.family_id == original_record.family_id

    assert store.consume_token(original) is None
    assert rotated_record.revoked is True
    assert store.consume_token(rotated) is None


def test_issue_rejects_past_expiry():
    store = RefreshTokenStore()

    with pytest.raises(ValueError):
        store.issue_token("alice", "client123", {"binding_method": "x"}, 1)


def test_consume_unknown_and_empty_tokens_fail_closed():
    store = RefreshTokenStore()

    assert store.consume_token("missing-token") is None
    assert store.consume_token("") is None
    assert store.consume_token(None) is None


def test_expired_token_is_rejected_and_marked_revoked():
    store = RefreshTokenStore()
    token = store.issue_token(
        "alice",
        "client123",
        build_refresh_binding_metadata(_session()),
        2_000_000_000,
    )
    record = store._lookup_token(token)
    record.expires_at = 1

    assert store.consume_token(token) is None
    assert record.revoked is True


def test_revoke_family_returns_false_for_unknown_token():
    store = RefreshTokenStore()

    assert store.revoke_family("missing-token") is False


def test_rotate_rejects_invalid_inputs():
    store = RefreshTokenStore()
    token = store.issue_token(
        "alice",
        "client123",
        build_refresh_binding_metadata(_session()),
        2_000_000_000,
    )

    with pytest.raises(ValueError):
        store.rotate_token(token, {}, 2_000_000_100)
    with pytest.raises(TypeError):
        store.rotate_token(token, {"binding_method": "x"}, "bad-expiry")
