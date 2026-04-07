import hashlib

import pytest

from kemtls.certs import create_certificate, validate_certificate


def test_certificate_roundtrip(monkeypatch, mldsa_keypair, mlkem_keypair):
    monkeypatch.setattr("kemtls.certs.get_timestamp", lambda: 1_700_000_000)

    ca_pk, ca_sk = mldsa_keypair
    kem_pk, _ = mlkem_keypair

    cert = create_certificate(
        subject="server-1",
        kem_pk=kem_pk,
        ca_sk=ca_sk,
        issuer="Root CA",
        valid_from=1_699_999_900,
        valid_to=1_700_000_100,
    )

    validated_kem_pk = validate_certificate(cert, ca_pk, "server-1")

    assert cert["issuer"] == "Root CA"
    assert cert["key_usage"] == "kemtls"
    assert validated_kem_pk == kem_pk


def test_certificate_rejects_wrong_ca_or_tampering(monkeypatch, mldsa_keypair, mlkem_keypair):
    monkeypatch.setattr("kemtls.certs.get_timestamp", lambda: 1_700_000_000)

    ca_pk, ca_sk = mldsa_keypair
    kem_pk, _ = mlkem_keypair

    cert = create_certificate(
        subject="server-1",
        kem_pk=kem_pk,
        ca_sk=ca_sk,
        issuer="Root CA",
        valid_from=1_699_999_900,
        valid_to=1_700_000_100,
    )

    with pytest.raises(ValueError, match="signature verification failed"):
        validate_certificate(cert, b"X" * 1952, "server-1")

    tampered = dict(cert)
    tampered["subject"] = "server-2"
    with pytest.raises(ValueError, match="signature verification failed"):
        validate_certificate(tampered, ca_pk, "server-2")


def test_certificate_rejects_time_window_and_identity_errors(monkeypatch, mldsa_keypair, mlkem_keypair):
    monkeypatch.setattr("kemtls.certs.get_timestamp", lambda: 1_700_000_000)

    ca_pk, ca_sk = mldsa_keypair
    kem_pk, _ = mlkem_keypair

    expired = create_certificate(
        subject="server-1",
        kem_pk=kem_pk,
        ca_sk=ca_sk,
        issuer="Root CA",
        valid_from=1_699_999_000,
        valid_to=1_699_999_999,
    )
    future = create_certificate(
        subject="server-1",
        kem_pk=kem_pk,
        ca_sk=ca_sk,
        issuer="Root CA",
        valid_from=1_700_000_001,
        valid_to=1_700_000_100,
    )
    valid = create_certificate(
        subject="server-1",
        kem_pk=kem_pk,
        ca_sk=ca_sk,
        issuer="Root CA",
        valid_from=1_699_999_900,
        valid_to=1_700_000_100,
    )

    with pytest.raises(ValueError, match="expired"):
        validate_certificate(expired, ca_pk, "server-1")

    with pytest.raises(ValueError, match="not yet valid"):
        validate_certificate(future, ca_pk, "server-1")

    with pytest.raises(ValueError, match="Identity mismatch"):
        validate_certificate(valid, ca_pk, "wrong-server")
