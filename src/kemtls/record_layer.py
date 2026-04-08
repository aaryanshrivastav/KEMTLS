"""
KEMTLS Record Layer

Provides secure framing and authenticated encryption (AEAD) for KEMTLS traffic.
Wire format: seq_number(8) | length(4) | ciphertext
"""

from __future__ import annotations

import struct
from socket import socket
from typing import Tuple

from crypto.aead import TAG_SIZE, open_, seal, xor_iv_with_seq
from rust_ext import record_layer as rust_record_layer

from .session import KEMTLSSession


def protect(key: bytes, iv: bytes, seq: int, plaintext: bytes, aad: bytes) -> bytes:
    """Encrypt a payload for a given sequence number and authenticated context."""
    nonce = xor_iv_with_seq(iv, seq)
    return seal(key, nonce, plaintext, aad)


def unprotect(key: bytes, iv: bytes, seq: int, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypt a payload for a given sequence number and authenticated context."""
    nonce = xor_iv_with_seq(iv, seq)
    return open_(key, nonce, ciphertext, aad)


class AEADPacketProtection:
    """Reusable AEAD protection helper shared by transport-specific framers."""

    def __init__(self, key: bytes, iv: bytes):
        self.key = key
        self.iv = iv

    def protect(self, seq: int, plaintext: bytes, aad: bytes) -> bytes:
        return protect(self.key, self.iv, seq, plaintext, aad)

    def unprotect(self, seq: int, ciphertext: bytes, aad: bytes) -> bytes:
        return unprotect(self.key, self.iv, seq, ciphertext, aad)


def frame_tcp_record(seq: int, payload: bytes) -> bytes:
    """Frame a protected TCP record as seq || length || payload."""
    return rust_record_layer.frame_record(
        seq,
        payload,
        fallback=_frame_record_python,
    )


def parse_tcp_record(data: bytes) -> Tuple[int, bytes]:
    """Parse a framed TCP record and return the sequence number and payload."""
    return rust_record_layer.parse_record(
        data,
        fallback=_parse_record_python,
    )


class KEMTLSRecordLayer:
    """
    Manages the encryption, decryption, and framing of KEMTLS TCP records.
    """

    def __init__(self, session: KEMTLSSession, sock: socket, is_client: bool):
        self.session = session
        self.sock = sock
        self.is_client = is_client

        # Sequence numbers
        self.send_seq = 0
        self.recv_seq = 0

        # Keys and IVs depend on role.
        if is_client:
            self.send_key = session.client_write_key
            self.send_iv = session.client_write_iv
            self.recv_key = session.server_write_key
            self.recv_iv = session.server_write_iv
        else:
            self.send_key = session.server_write_key
            self.send_iv = session.server_write_iv
            self.recv_key = session.client_write_key
            self.recv_iv = session.client_write_iv

        self.sender = AEADPacketProtection(self.send_key, self.send_iv)
        self.receiver = AEADPacketProtection(self.recv_key, self.recv_iv)

    def protect(self, seq: int, plaintext: bytes, aad: bytes) -> bytes:
        return self.sender.protect(seq, plaintext, aad)

    def unprotect(self, seq: int, ciphertext: bytes, aad: bytes) -> bytes:
        return self.receiver.unprotect(seq, ciphertext, aad)

    def send_record(self, plaintext: bytes):
        """Encrypt and send a TCP record."""
        if self.send_seq >= 1 << 64:
            raise OverflowError("Sequence number overflow")

        ciphertext_len = len(plaintext) + TAG_SIZE
        header = struct.pack(">QI", self.send_seq, ciphertext_len)
        ciphertext = self.protect(self.send_seq, plaintext, header)
        framed = frame_tcp_record(self.send_seq, ciphertext)

        self.sock.sendall(framed)
        self.send_seq += 1

    def recv_record(self) -> bytes:
        """Receive and decrypt a TCP record."""
        header = self._read_n_bytes(12)
        seq = int.from_bytes(header[:8], "big")
        length = int.from_bytes(header[8:12], "big")

        if seq != self.recv_seq:
            raise ValueError(f"Sequence mismatch: expected {self.recv_seq}, got {seq}")

        ciphertext = self._read_n_bytes(length)
        parsed_seq, payload = parse_tcp_record(header + ciphertext)
        if parsed_seq != seq:
            raise ValueError("record framing parse mismatch")

        plaintext = self.unprotect(self.recv_seq, payload, header)

        self.recv_seq += 1
        return plaintext

    def _read_n_bytes(self, n: int) -> bytes:
        """Helper to read exactly n bytes from the socket."""
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise EOFError("Connection closed by peer")
            data += chunk
        return data


def for_client(session: KEMTLSSession, sock: socket) -> KEMTLSRecordLayer:
    return KEMTLSRecordLayer(session, sock, True)


def for_server(session: KEMTLSSession, sock: socket) -> KEMTLSRecordLayer:
    return KEMTLSRecordLayer(session, sock, False)


def _frame_record_python(seq: int, payload: bytes) -> bytes:
    return struct.pack(">QI", seq, len(payload)) + payload


def _parse_record_python(data: bytes) -> Tuple[int, bytes]:
    if len(data) < 12:
        raise ValueError("record too short")

    seq, length = struct.unpack(">QI", data[:12])
    expected = 12 + length
    if len(data) != expected:
        raise ValueError("invalid record length")

    return seq, data[12:]

