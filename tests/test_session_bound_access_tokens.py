import time
from dataclasses import dataclass

import hashlib

from crypto.ml_dsa import MLDSA65
from oidc.jwt_handler import PQJWT
from oidc.session_binding import build_access_token_binding_claim, verify_access_token_binding_claim
from oidc.userinfo_endpoints import UserInfoEndpoint


@dataclass
class DummySession:
    session_binding_id: bytes
    refresh_binding_id: bytes
    handshake_mode: str = "baseline"


ISSUER_PUBLIC_KEY, ISSUER_SECRET_KEY = MLDSA65.generate_keypair()


def _patch_signatures(monkeypatch):
    pass


def _make_access_token(session):
    return PQJWT().create_access_token(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "aud": "client123",
            "client_id": "client123",
            "scope": "openid profile email",
            "exp": int(time.time()) + 600,
        },
        ISSUER_SECRET_KEY,
        cnf_claim=build_access_token_binding_claim(session),
    )


def test_session_bound_claim_verifies_on_original_session():
    session = DummySession(b"a" * 32, b"b" * 32)
    claim = build_access_token_binding_claim(session)

    assert verify_access_token_binding_claim(claim, session) is True


def test_session_bound_claim_and_userinfo_reject_replay(monkeypatch):
    _patch_signatures(monkeypatch)
    original_session = DummySession(b"a" * 32, b"b" * 32)
    replay_session = DummySession(b"z" * 32, b"b" * 32)
    endpoint = UserInfoEndpoint(
        ISSUER_PUBLIC_KEY,
        issuer="https://issuer.example",
        audience="client123",
    )
    token = _make_access_token(original_session)

    payload, status = endpoint.handle_userinfo_request(token, session=replay_session)

    assert verify_access_token_binding_claim(
        build_access_token_binding_claim(original_session),
        replay_session,
    ) is False
    assert status == 401
    assert payload["error"] == "binding_mismatch"


def test_session_bound_access_tokens_fail_closed_without_session(monkeypatch):
    _patch_signatures(monkeypatch)
    session = DummySession(b"a" * 32, b"b" * 32)
    endpoint = UserInfoEndpoint(
        ISSUER_PUBLIC_KEY,
        issuer="https://issuer.example",
        audience="client123",
    )

    payload, status = endpoint.handle_userinfo_request(_make_access_token(session), session=None)

    assert status == 401
    assert payload["error"] == "missing_session_context"
