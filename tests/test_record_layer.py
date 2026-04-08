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


def test_record_layer_roundtrip_uses_full_header_as_aad():
    client_sock, server_sock = _socket_pair()
    client = KEMTLSRecordLayer(_session(), client_sock, is_client=True)
    server = KEMTLSRecordLayer(_session(), server_sock, is_client=False)

    client.send_record(b"hello")
    plaintext = server.recv_record()

    assert plaintext == b"hello"
    assert server.recv_seq == 1


def test_record_layer_rejects_wrong_sequence():
    client_sock, server_sock = _socket_pair()
    client = KEMTLSRecordLayer(_session(), client_sock, is_client=True)
    server = KEMTLSRecordLayer(_session(), server_sock, is_client=False)

    client.send_record(b"hello")
    server_sock.buffer[:8] = struct.pack(">Q", 9)

    with pytest.raises(ValueError, match="Sequence mismatch"):
        server.recv_record()


def test_record_layer_rejects_header_aad_mismatch():
    client_sock, server_sock = _socket_pair()
    client = KEMTLSRecordLayer(_session(), client_sock, is_client=True)
    server = KEMTLSRecordLayer(_session(), server_sock, is_client=False)

    client.send_record(b"hello")
    server_sock.buffer[8:12] = struct.pack(">I", len(b"Xhello") - 1)

    with pytest.raises(ValueError):
        server.recv_record()


def test_record_layer_raises_on_partial_read():
    client_sock, server_sock = _socket_pair()
    client = KEMTLSRecordLayer(_session(), client_sock, is_client=True)
    server = KEMTLSRecordLayer(_session(), server_sock, is_client=False)

    client.send_record(b"hello")
    del server_sock.buffer[-2:]

    with pytest.raises(EOFError, match="Connection closed by peer"):
        server.recv_record()


def test_send_record_encrypts_once_and_header_matches_ciphertext(monkeypatch):
    client_sock, server_sock = _socket_pair()
    client = KEMTLSRecordLayer(_session(), client_sock, is_client=True)

    call_count = {"value": 0}

    def _fake_seal(key, nonce, plaintext, aad):
        call_count["value"] += 1
        # Return deterministic ciphertext length = plaintext + tag(16)
        return b"C" * (len(plaintext) + 16)

    monkeypatch.setattr("kemtls.record_layer.seal", _fake_seal)

    client.send_record(b"hello")

    assert call_count["value"] == 1
    frame = bytes(server_sock.buffer)
    assert len(frame) >= 12
    length = struct.unpack(">I", frame[8:12])[0]
    assert length == len(frame[12:])
