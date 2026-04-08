"""
KEMTLS Record Layer

Provides secure framing and authenticated encryption (AEAD) for KEMTLS traffic.
Wire format: seq_number(8) | length(4) | ciphertext
"""

import struct
from socket import socket
from typing import Tuple
from .session import KEMTLSSession
from crypto.aead import TAG_SIZE, seal, open_, xor_iv_with_seq
from rust_ext import record_layer as rust_record_layer


class KEMTLSRecordLayer:
    """
    Manages the encryption, decryption, and framing of KEMTLS records.
    """
    
    def __init__(self, session: KEMTLSSession, sock: socket, is_client: bool):
        self.session = session
        self.sock = sock
        self.is_client = is_client
        
        # Sequence numbers
        self.send_seq = 0
        self.recv_seq = 0
        
        # Keys and IVs - depend on role
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

    def send_record(self, plaintext: bytes):
        """Encrypt and send a record."""
        if self.send_seq >= 1 << 64:
            raise OverflowError("Sequence number overflow")
            
        nonce = xor_iv_with_seq(self.send_iv, self.send_seq)
        
        # AAD = Header (Seq + Length)
        # We'll calculate length after encryption
        # For KEMTLS records, we'll use a 4-byte length field
        
        # ChaCha20-Poly1305 appends a fixed 16-byte tag, so ciphertext length is known upfront.
        ciphertext_len = len(plaintext) + TAG_SIZE
        header = struct.pack(">QI", self.send_seq, ciphertext_len)
        ciphertext = seal(self.send_key, nonce, plaintext, header)
        framed = rust_record_layer.frame_record(
            self.send_seq,
            ciphertext,
            fallback=_frame_record_python,
        )

        self.sock.sendall(framed)
        self.send_seq += 1

    def recv_record(self) -> bytes:
        """Receive and decrypt a record."""
        # 1. Read Header
        header = self._read_n_bytes(12)
        seq = int.from_bytes(header[:8], "big")
        length = int.from_bytes(header[8:12], "big")
        
        if seq != self.recv_seq:
            raise ValueError(f"Sequence mismatch: expected {self.recv_seq}, got {seq}")
            
        # 2. Read Ciphertext
        ciphertext = self._read_n_bytes(length)
        parsed_seq, ciphertext = rust_record_layer.parse_record(
            header + ciphertext,
            fallback=_parse_record_python,
        )
        if parsed_seq != seq:
            raise ValueError("record framing parse mismatch")
        
        # 3. Decrypt
        nonce = xor_iv_with_seq(self.recv_iv, self.recv_seq)
        plaintext = open_(self.recv_key, nonce, ciphertext, header)
        
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
