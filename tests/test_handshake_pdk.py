import pytest

from crypto.ml_dsa import MLDSA65
from crypto.ml_kem import MLKEM768
from kemtls.certs import create_certificate
from kemtls.handshake import ClientHandshake, ServerHandshake
from kemtls.pdk import PDKTrustStore


CA_PUBLIC_KEY, CA_SECRET_KEY = MLDSA65.generate_keypair()
SERVER_LT_PUBLIC_KEY, SERVER_LT_SECRET_KEY = MLKEM768.generate_keypair()


def test_pdk_handshake_completes_with_trusted_key_id(monkeypatch):
    monkeypatch.setattr("kemtls.handshake.generate_random_string", lambda length: "p" * length)

    pdk_store = PDKTrustStore()
    pdk_store.add_entry("key-1", "server-1", SERVER_LT_PUBLIC_KEY)

    server = ServerHandshake(
        server_identity="server-1",
        server_lt_sk=SERVER_LT_SECRET_KEY,
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
    monkeypatch.setattr("kemtls.handshake.generate_random_string", lambda length: "p" * length)

    pdk_store = PDKTrustStore()
    pdk_store.add_entry("key-1", "server-1", SERVER_LT_PUBLIC_KEY)

    server = ServerHandshake(
        server_identity="server-1",
        server_lt_sk=SERVER_LT_SECRET_KEY,
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
    monkeypatch.setattr("kemtls.handshake.generate_random_string", lambda length: "p" * length)

    pdk_store = PDKTrustStore()
    pdk_store.add_entry("key-1", "server-1", SERVER_LT_PUBLIC_KEY)

    server = ServerHandshake(
        server_identity="server-1",
        server_lt_sk=SERVER_LT_SECRET_KEY,
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
    monkeypatch.setattr("kemtls.handshake.generate_random_string", lambda length: "p" * length)

    cert = create_certificate(
        subject="server-1",
        kem_pk=SERVER_LT_PUBLIC_KEY,
        ca_sk=CA_SECRET_KEY,
        issuer="Root CA",
        valid_from=0,
        valid_to=4_000_000_000,
    )

    client = ClientHandshake(
        expected_identity="server-1",
        ca_pk=CA_PUBLIC_KEY,
        pdk_store=PDKTrustStore(),
        mode="auto",
    )
    server = ServerHandshake(
        server_identity="server-1",
        server_lt_sk=SERVER_LT_SECRET_KEY,
        cert=cert,
    )

    ch = client.client_hello()
    sh = server.process_client_hello(ch)
    _, session_client = client.process_server_hello(sh)

    assert session_client.handshake_mode == "baseline"
