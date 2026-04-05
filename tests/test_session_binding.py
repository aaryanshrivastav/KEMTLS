from dataclasses import dataclass

from oidc.session_binding import (
    BINDING_METHOD,
    build_access_token_binding_claim,
    build_refresh_binding_metadata,
    verify_access_token_binding_claim,
    verify_refresh_binding_metadata,
)


@dataclass
class _FakeSession:
    session_binding_id: bytes
    refresh_binding_id: bytes


def test_access_token_binding_claim_creation_and_verification():
    session = _FakeSession(
        session_binding_id=b"\x01" * 32,
        refresh_binding_id=b"\x02" * 32,
    )

    claim = build_access_token_binding_claim(session)

    assert claim["cnf"]["kmt"] == BINDING_METHOD
    assert verify_access_token_binding_claim(claim, session) is True


def test_access_token_binding_mismatch_on_different_session():
    first = _FakeSession(
        session_binding_id=b"\x01" * 32,
        refresh_binding_id=b"\x02" * 32,
    )
    second = _FakeSession(
        session_binding_id=b"\x03" * 32,
        refresh_binding_id=b"\x04" * 32,
    )

    claim = build_access_token_binding_claim(first)

    assert verify_access_token_binding_claim(claim, second) is False


def test_refresh_binding_mismatch_on_different_session():
    first = _FakeSession(
        session_binding_id=b"\x05" * 32,
        refresh_binding_id=b"\x06" * 32,
    )
    second = _FakeSession(
        session_binding_id=b"\x07" * 32,
        refresh_binding_id=b"\x08" * 32,
    )

    metadata = build_refresh_binding_metadata(first)

    assert verify_refresh_binding_metadata(metadata, first) is True
    assert verify_refresh_binding_metadata(metadata, second) is False


def test_binding_verification_fails_closed_when_session_is_missing():
    claim = {"cnf": {"kmt": BINDING_METHOD, "kbh": "abc"}}
    metadata = {"binding_method": BINDING_METHOD, "binding_hash": "abc"}

    assert verify_access_token_binding_claim(claim, None) is False
    assert verify_refresh_binding_metadata(metadata, None) is False


def test_builders_require_populated_bytes():
    class _BadSession:
        session_binding_id = None
        refresh_binding_id = b""

    import pytest

    with pytest.raises(ValueError, match="session_binding_id"):
        build_access_token_binding_claim(_BadSession())
    with pytest.raises(ValueError, match="refresh_binding_id"):
        build_refresh_binding_metadata(_BadSession())
