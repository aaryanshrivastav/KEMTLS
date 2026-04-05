import struct

import pytest

from kemtls.record_layer import KEMTLSRecordLayer
from kemtls.session import KEMTLSSession


class _MemorySocket:
    def __init__(self):
        self.buffer = bytearray()
        self.peer = None

    def connect(self, peer):
        self.peer = peer

    def sendall(self, data: bytes):
        self.peer.buffer.extend(data)

    def recv(self, size: int) -> bytes:
        if not self.buffer:
            return b""
        chunk = bytes(self.buffer[:size])
        del self.buffer[:size]
        return chunk


def _socket_pair():
    left = _MemorySocket()
    right = _MemorySocket()
    left.connect(right)
    right.connect(left)
    return left, right


def _session():
    return KEMTLSSession(
        session_id="sess-1",
        peer_identity="server-1",
        handshake_mode="baseline",
        client_write_key=b"A" * 32,
        client_write_iv=b"I" * 12,
        server_write_key=b"B" * 32,
        server_write_iv=b"J" * 12,
    )


def test_record_layer_roundtrip_uses_full_header_as_aad(monkeypatch):
    captured_aads = []

    def fake_seal(key, nonce, plaintext, aad):
        captured_aads.append(aad)
        return b"X" + plaintext

    def fake_open(key, nonce, ciphertext, aad):
        assert aad == captured_aads[-1]
        return ciphertext[1:]

    monkeypatch.setattr("kemtls.record_layer.seal", fake_seal)
    monkeypatch.setattr("kemtls.record_layer.open_", fake_open)

    client_sock, server_sock = _socket_pair()
    client = KEMTLSRecordLayer(_session(), client_sock, is_client=True)
    server = KEMTLSRecordLayer(_session(), server_sock, is_client=False)

    client.send_record(b"hello")
    plaintext = server.recv_record()

    assert plaintext == b"hello"
    assert captured_aads[-1] == struct.pack(">QI", 0, len(b"Xhello"))


def test_record_layer_rejects_wrong_sequence(monkeypatch):
    monkeypatch.setattr("kemtls.record_layer.seal", lambda key, nonce, plaintext, aad: b"X" + plaintext)
    monkeypatch.setattr("kemtls.record_layer.open_", lambda key, nonce, ciphertext, aad: ciphertext[1:])

    client_sock, server_sock = _socket_pair()
    client = KEMTLSRecordLayer(_session(), client_sock, is_client=True)
    server = KEMTLSRecordLayer(_session(), server_sock, is_client=False)

    client.send_record(b"hello")
    server_sock.buffer[:8] = struct.pack(">Q", 9)

    with pytest.raises(ValueError, match="Sequence mismatch"):
        server.recv_record()


def test_record_layer_rejects_header_aad_mismatch(monkeypatch):
    expected_header = None

    def fake_seal(key, nonce, plaintext, aad):
        nonlocal expected_header
        expected_header = aad
        return b"X" + plaintext

    def fake_open(key, nonce, ciphertext, aad):
        if aad != expected_header:
            raise ValueError("AAD mismatch")
        return ciphertext[1:]

    monkeypatch.setattr("kemtls.record_layer.seal", fake_seal)
    monkeypatch.setattr("kemtls.record_layer.open_", fake_open)

    client_sock, server_sock = _socket_pair()
    client = KEMTLSRecordLayer(_session(), client_sock, is_client=True)
    server = KEMTLSRecordLayer(_session(), server_sock, is_client=False)

    client.send_record(b"hello")
    server_sock.buffer[8:12] = struct.pack(">I", len(b"Xhello") - 1)

    with pytest.raises(ValueError, match="AAD mismatch"):
        server.recv_record()


def test_record_layer_raises_on_partial_read(monkeypatch):
    monkeypatch.setattr("kemtls.record_layer.seal", lambda key, nonce, plaintext, aad: b"X" + plaintext)
    monkeypatch.setattr("kemtls.record_layer.open_", lambda key, nonce, ciphertext, aad: ciphertext[1:])

    client_sock, server_sock = _socket_pair()
    client = KEMTLSRecordLayer(_session(), client_sock, is_client=True)
    server = KEMTLSRecordLayer(_session(), server_sock, is_client=False)

    client.send_record(b"hello")
    del server_sock.buffer[-2:]

    with pytest.raises(EOFError, match="Connection closed by peer"):
        server.recv_record()
