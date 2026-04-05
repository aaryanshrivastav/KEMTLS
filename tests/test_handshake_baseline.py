import hashlib
from itertools import count

import pytest

from kemtls.handshake import ClientHandshake, ServerHandshake
from utils.encoding import base64url_decode
from utils.serialization import deserialize_message, serialize_message


def _install_fake_mlkem(monkeypatch):
    counter = count(1)

    def fake_generate_keypair():
        marker = next(counter).to_bytes(1, "big")
        return marker * 1184, marker * 2400

    def fake_encapsulate(public_key: bytes):
        marker = public_key[:1]
        ciphertext = marker * 1088
        shared_secret = hashlib.sha256(b"ss" + marker).digest()
        return ciphertext, shared_secret

    def fake_decapsulate(secret_key: bytes, ciphertext: bytes):
        marker = secret_key[:1]
        assert ciphertext[:1] == marker
        return hashlib.sha256(b"ss" + marker).digest()

    monkeypatch.setattr("kemtls.handshake.MLKEM768.generate_keypair", fake_generate_keypair)
    monkeypatch.setattr("kemtls.handshake.MLKEM768.encapsulate", fake_encapsulate)
    monkeypatch.setattr("kemtls.handshake.MLKEM768.decapsulate", fake_decapsulate)


def _install_fake_certificate_validation(monkeypatch):
    def fake_validate_certificate(cert, ca_pk, expected_identity):
        if cert["subject"] != expected_identity:
            raise ValueError("Identity mismatch")
        return base64url_decode(cert["kem_public_key"])

    monkeypatch.setattr("kemtls.handshake.validate_certificate", fake_validate_certificate)


def test_baseline_handshake_completes_and_populates_session(monkeypatch):
    _install_fake_mlkem(monkeypatch)
    _install_fake_certificate_validation(monkeypatch)
    monkeypatch.setattr("kemtls.handshake.generate_random_string", lambda length: "s" * length)

    server = ServerHandshake(
        server_identity="server-1",
        server_lt_sk=b"L" * 2400,
        cert={"subject": "server-1", "kem_public_key": "TA"},
    )
    client = ClientHandshake(
        expected_identity="server-1",
        ca_pk=b"C" * 1952,
        mode="baseline",
    )

    ch = client.client_hello()
    sh = server.process_client_hello(ch)
    cke, session_client = client.process_server_hello(sh)

    assert session_client.handshake_mode == "baseline"
    assert session_client.client_app_secret is None
    assert session_client.exporter_secret is None
    assert session_client.session_binding_id is None

    sf = server.process_client_key_exchange(cke)
    session_client = client.process_server_finished(sf, session_client)
    cf = client.client_finished()
    session_server = server.verify_client_finished(cf)

    assert session_client.client_app_secret is not None
    assert session_client.server_app_secret is not None
    assert session_client.exporter_secret is not None
    assert session_client.session_binding_id
    assert session_client.refresh_binding_id
    assert session_server.handshake_mode == "baseline"
    assert session_server.client_app_secret is not None
    assert session_server.session_binding_id


def test_baseline_handshake_rejects_identity_mismatch(monkeypatch):
    _install_fake_mlkem(monkeypatch)
    _install_fake_certificate_validation(monkeypatch)
    monkeypatch.setattr("kemtls.handshake.generate_random_string", lambda length: "s" * length)

    server = ServerHandshake(
        server_identity="server-1",
        server_lt_sk=b"L" * 2400,
        cert={"subject": "server-1", "kem_public_key": "TA"},
    )
    client = ClientHandshake(
        expected_identity="wrong-server",
        ca_pk=b"C" * 1952,
        mode="baseline",
    )

    ch = client.client_hello()
    sh = server.process_client_hello(ch)

    with pytest.raises(ValueError, match="Identity mismatch"):
        client.process_server_hello(sh)


def test_baseline_handshake_rejects_tampered_server_finished(monkeypatch):
    _install_fake_mlkem(monkeypatch)
    _install_fake_certificate_validation(monkeypatch)
    monkeypatch.setattr("kemtls.handshake.generate_random_string", lambda length: "s" * length)

    server = ServerHandshake(
        server_identity="server-1",
        server_lt_sk=b"L" * 2400,
        cert={"subject": "server-1", "kem_public_key": "TA"},
    )
    client = ClientHandshake(
        expected_identity="server-1",
        ca_pk=b"C" * 1952,
        mode="baseline",
    )

    ch = client.client_hello()
    sh = server.process_client_hello(ch)
    cke, session_client = client.process_server_hello(sh)
    sf = deserialize_message(server.process_client_key_exchange(cke))
    sf["mac"] = "A" * len(sf["mac"])

    with pytest.raises(ValueError, match="ServerFinished MAC verification failed"):
        client.process_server_finished(serialize_message(sf), session_client)
