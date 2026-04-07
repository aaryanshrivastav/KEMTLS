import pytest

from crypto.ml_dsa import MLDSA65
from crypto.ml_kem import MLKEM768
from kemtls.certs import create_certificate
from kemtls.handshake import ClientHandshake, ServerHandshake
from utils.serialization import deserialize_message, serialize_message


CA_PUBLIC_KEY, CA_SECRET_KEY = MLDSA65.generate_keypair()
SERVER_LT_PUBLIC_KEY, SERVER_LT_SECRET_KEY = MLKEM768.generate_keypair()


def test_baseline_handshake_completes_and_populates_session(monkeypatch):
    monkeypatch.setattr("kemtls.handshake.generate_random_string", lambda length: "s" * length)

    cert = create_certificate(
        subject="server-1",
        kem_pk=SERVER_LT_PUBLIC_KEY,
        ca_sk=CA_SECRET_KEY,
        issuer="Root CA",
        valid_from=0,
        valid_to=4_000_000_000,
    )

    server = ServerHandshake(
        server_identity="server-1",
        server_lt_sk=SERVER_LT_SECRET_KEY,
        cert=cert,
    )
    client = ClientHandshake(
        expected_identity="server-1",
        ca_pk=CA_PUBLIC_KEY,
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
    monkeypatch.setattr("kemtls.handshake.generate_random_string", lambda length: "s" * length)

    cert = create_certificate(
        subject="server-1",
        kem_pk=SERVER_LT_PUBLIC_KEY,
        ca_sk=CA_SECRET_KEY,
        issuer="Root CA",
        valid_from=0,
        valid_to=4_000_000_000,
    )

    server = ServerHandshake(
        server_identity="server-1",
        server_lt_sk=SERVER_LT_SECRET_KEY,
        cert=cert,
    )
    client = ClientHandshake(
        expected_identity="wrong-server",
        ca_pk=CA_PUBLIC_KEY,
        mode="baseline",
    )

    ch = client.client_hello()
    sh = server.process_client_hello(ch)

    with pytest.raises(ValueError, match="Identity mismatch"):
        client.process_server_hello(sh)


def test_baseline_handshake_rejects_tampered_server_finished(monkeypatch):
    monkeypatch.setattr("kemtls.handshake.generate_random_string", lambda length: "s" * length)

    cert = create_certificate(
        subject="server-1",
        kem_pk=SERVER_LT_PUBLIC_KEY,
        ca_sk=CA_SECRET_KEY,
        issuer="Root CA",
        valid_from=0,
        valid_to=4_000_000_000,
    )

    server = ServerHandshake(
        server_identity="server-1",
        server_lt_sk=SERVER_LT_SECRET_KEY,
        cert=cert,
    )
    client = ClientHandshake(
        expected_identity="server-1",
        ca_pk=CA_PUBLIC_KEY,
        mode="baseline",
    )

    ch = client.client_hello()
    sh = server.process_client_hello(ch)
    cke, session_client = client.process_server_hello(sh)
    sf = deserialize_message(server.process_client_key_exchange(cke))
    sf["mac"] = "A" * len(sf["mac"])

    with pytest.raises(ValueError, match="ServerFinished MAC verification failed"):
        client.process_server_finished(serialize_message(sf), session_client)
