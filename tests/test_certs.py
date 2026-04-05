import hashlib

import pytest

from kemtls.certs import create_certificate, validate_certificate


def _fake_sign(secret_key: bytes, message: bytes) -> bytes:
    return hashlib.sha256(secret_key[:1] + message).digest()


def _fake_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    return signature == hashlib.sha256(public_key[:1] + message).digest()


def test_certificate_roundtrip(monkeypatch):
    monkeypatch.setattr("kemtls.certs.MLDSA65.sign", _fake_sign)
    monkeypatch.setattr("kemtls.certs.MLDSA65.verify", _fake_verify)
    monkeypatch.setattr("kemtls.certs.get_timestamp", lambda: 1_700_000_000)

    cert = create_certificate(
        subject="server-1",
        kem_pk=b"K" * 1184,
        ca_sk=b"C" * 4032,
        issuer="Root CA",
        valid_from=1_699_999_900,
        valid_to=1_700_000_100,
    )

    kem_pk = validate_certificate(cert, b"C" * 1952, "server-1")

    assert cert["issuer"] == "Root CA"
    assert cert["key_usage"] == "kemtls"
    assert kem_pk == b"K" * 1184


def test_certificate_rejects_wrong_ca_or_tampering(monkeypatch):
    monkeypatch.setattr("kemtls.certs.MLDSA65.sign", _fake_sign)
    monkeypatch.setattr("kemtls.certs.MLDSA65.verify", _fake_verify)
    monkeypatch.setattr("kemtls.certs.get_timestamp", lambda: 1_700_000_000)

    cert = create_certificate(
        subject="server-1",
        kem_pk=b"K" * 1184,
        ca_sk=b"C" * 4032,
        issuer="Root CA",
        valid_from=1_699_999_900,
        valid_to=1_700_000_100,
    )

    with pytest.raises(ValueError, match="signature verification failed"):
        validate_certificate(cert, b"X" * 1952, "server-1")

    tampered = dict(cert)
    tampered["subject"] = "server-2"
    with pytest.raises(ValueError, match="signature verification failed"):
        validate_certificate(tampered, b"C" * 1952, "server-2")


def test_certificate_rejects_time_window_and_identity_errors(monkeypatch):
    monkeypatch.setattr("kemtls.certs.MLDSA65.sign", _fake_sign)
    monkeypatch.setattr("kemtls.certs.MLDSA65.verify", _fake_verify)
    monkeypatch.setattr("kemtls.certs.get_timestamp", lambda: 1_700_000_000)

    expired = create_certificate(
        subject="server-1",
        kem_pk=b"K" * 1184,
        ca_sk=b"C" * 4032,
        issuer="Root CA",
        valid_from=1_699_999_000,
        valid_to=1_699_999_999,
    )
    future = create_certificate(
        subject="server-1",
        kem_pk=b"K" * 1184,
        ca_sk=b"C" * 4032,
        issuer="Root CA",
        valid_from=1_700_000_001,
        valid_to=1_700_000_100,
    )
    valid = create_certificate(
        subject="server-1",
        kem_pk=b"K" * 1184,
        ca_sk=b"C" * 4032,
        issuer="Root CA",
        valid_from=1_699_999_900,
        valid_to=1_700_000_100,
    )

    with pytest.raises(ValueError, match="expired"):
        validate_certificate(expired, b"C" * 1952, "server-1")

    with pytest.raises(ValueError, match="not yet valid"):
        validate_certificate(future, b"C" * 1952, "server-1")

    with pytest.raises(ValueError, match="Identity mismatch"):
        validate_certificate(valid, b"C" * 1952, "wrong-server")
