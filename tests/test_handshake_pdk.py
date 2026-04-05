import hashlib
from itertools import count

import pytest

from kemtls.handshake import ClientHandshake, ServerHandshake
from kemtls.pdk import PDKTrustStore
from utils.encoding import base64url_decode


def _install_fake_mlkem(monkeypatch):
    counter = count(1)

    def fake_generate_keypair():
        marker = next(counter).to_bytes(1, "big")
        return marker * 1184, marker * 2400

    def fake_encapsulate(public_key: bytes):
        marker = public_key[:1]
        return marker * 1088, hashlib.sha256(b"ss" + marker).digest()

    def fake_decapsulate(secret_key: bytes, ciphertext: bytes):
        marker = secret_key[:1]
        assert ciphertext[:1] == marker
        return hashlib.sha256(b"ss" + marker).digest()

    monkeypatch.setattr("kemtls.handshake.MLKEM768.generate_keypair", fake_generate_keypair)
    monkeypatch.setattr("kemtls.handshake.MLKEM768.encapsulate", fake_encapsulate)
    monkeypatch.setattr("kemtls.handshake.MLKEM768.decapsulate", fake_decapsulate)


def test_pdk_handshake_completes_with_trusted_key_id(monkeypatch):
    _install_fake_mlkem(monkeypatch)
    monkeypatch.setattr("kemtls.handshake.generate_random_string", lambda length: "p" * length)

    pdk_store = PDKTrustStore()
    pdk_store.add_entry("key-1", "server-1", b"K" * 1184)

    server = ServerHandshake(
        server_identity="server-1",
        server_lt_sk=b"K" * 2400,
        pdk_key_id="key-1",
    )
    client = ClientHandshake(
        expected_identity="server-1",
        pdk_store=pdk_store,
        mode="pdk",
    )

    ch = client.client_hello()
    sh = server.process_client_hello(ch)
    cke, session_client = client.process_server_hello(sh)
    sf = server.process_client_key_exchange(cke)
    session_client = client.process_server_finished(sf, session_client)
    cf = client.client_finished()
    session_server = server.verify_client_finished(cf)

    assert session_client.handshake_mode == "pdk"
    assert session_client.trusted_key_id == "key-1"
    assert session_server.trusted_key_id == "key-1"
    assert session_client.session_binding_id
    assert session_server.refresh_binding_id


def test_pdk_handshake_rejects_identity_mismatch(monkeypatch):
    _install_fake_mlkem(monkeypatch)
    monkeypatch.setattr("kemtls.handshake.generate_random_string", lambda length: "p" * length)

    pdk_store = PDKTrustStore()
    pdk_store.add_entry("key-1", "server-1", b"K" * 1184)

    server = ServerHandshake(
        server_identity="server-1",
        server_lt_sk=b"K" * 2400,
        pdk_key_id="key-1",
    )
    client = ClientHandshake(
        expected_identity="wrong-server",
        pdk_store=pdk_store,
        mode="pdk",
    )

    ch = client.client_hello()
    sh = server.process_client_hello(ch)

    with pytest.raises(ValueError, match="Identity mismatch"):
        client.process_server_hello(sh)


def test_auto_mode_prefers_pdk_when_available(monkeypatch):
    _install_fake_mlkem(monkeypatch)
    monkeypatch.setattr("kemtls.handshake.generate_random_string", lambda length: "p" * length)

    pdk_store = PDKTrustStore()
    pdk_store.add_entry("key-1", "server-1", b"K" * 1184)

    server = ServerHandshake(
        server_identity="server-1",
        server_lt_sk=b"K" * 2400,
        cert={"subject": "server-1", "kem_public_key": "S0s"},
        pdk_key_id="key-1",
    )
    client = ClientHandshake(
        expected_identity="server-1",
        ca_pk=b"C" * 1952,
        pdk_store=pdk_store,
        mode="auto",
    )

    ch = client.client_hello()
    sh = server.process_client_hello(ch)
    _, session_client = client.process_server_hello(sh)

    assert session_client.handshake_mode == "pdk"


def test_auto_mode_falls_back_to_baseline_when_pdk_not_locally_trusted(monkeypatch):
    _install_fake_mlkem(monkeypatch)
    monkeypatch.setattr("kemtls.handshake.generate_random_string", lambda length: "p" * length)

    def fake_validate_certificate(cert, ca_pk, expected_identity):
        if cert["subject"] != expected_identity:
            raise ValueError("Identity mismatch")
        return base64url_decode(cert["kem_public_key"])

    monkeypatch.setattr("kemtls.handshake.validate_certificate", fake_validate_certificate)

    client = ClientHandshake(
        expected_identity="server-1",
        ca_pk=b"C" * 1952,
        pdk_store=PDKTrustStore(),
        mode="auto",
    )
    server = ServerHandshake(
        server_identity="server-1",
        server_lt_sk=b"K" * 2400,
        cert={"subject": "server-1", "kem_public_key": "S0s"},
    )

    ch = client.client_hello()
    sh = server.process_client_hello(ch)
    _, session_client = client.process_server_hello(sh)

    assert session_client.handshake_mode == "baseline"
