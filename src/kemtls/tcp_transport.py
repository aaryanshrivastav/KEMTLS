"""TCP transport implementation for KEMTLS."""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, Tuple

from .handshake import ClientHandshake, ServerHandshake
from .record_layer import for_client, for_server
from .transport import KEMTLSTransport

if TYPE_CHECKING:
    from flask import Flask


def handle_application_session(
    app: "Flask",
    transport: "KEMTLSTCPServerConnection",
) -> None:
    """Process one or more decrypted HTTP requests on an established session."""
    from ._http_bridge import call_flask_app, parse_http_request

    if transport.session is None:
        raise RuntimeError("transport session has not been established")

    while True:
        try:
            raw_request = transport.recv_application()
        except EOFError:
            break

        request_map = parse_http_request(raw_request)
        response_bytes = call_flask_app(app, transport.session, raw_request)
        transport.send_application(response_bytes)

        connection_header = str(request_map.get("headers", {}).get("connection", "")).lower()
        if connection_header == "close":
            break


class KEMTLSTCPClientTransport(KEMTLSTransport):
    """Client-side TCP transport that preserves the current KEMTLS behavior."""

    def __init__(
        self,
        expected_identity: str,
        ca_pk: Optional[bytes] = None,
        pdk_store=None,
        mode: str = "auto",
        collector: Optional[Any] = None,
    ):
        super().__init__()
        self.expected_identity = expected_identity
        self.ca_pk = ca_pk
        self.pdk_store = pdk_store
        self.mode = mode
        self.collector = collector
        self.sock: Optional[socket.socket] = None
        self.record_layer = None
        self.connected_host: Optional[str] = None
        self.connected_port: Optional[int] = None

    def connect(self, host: str, port: int) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))

        if self.collector:
            self.collector.start_hct()

        handshake = ClientHandshake(
            self.expected_identity,
            self.ca_pk,
            self.pdk_store,
            self.mode,
            collector=self.collector,
        )

        client_hello = handshake.client_hello()
        self.send_handshake(client_hello, sock=sock)

        server_hello = self.recv_handshake(sock=sock)
        if self.collector and hasattr(self.collector, "record_ttfb"):
            self.collector.record_ttfb()

        client_key_exchange, session = handshake.process_server_hello(server_hello)
        self.send_handshake(client_key_exchange, sock=sock)

        server_finished = self.recv_handshake(sock=sock)
        session = handshake.process_server_finished(server_finished, session)

        client_finished = handshake.client_finished()
        self.send_handshake(client_finished, sock=sock)

        session.transport = "tcp"
        self.session = session
        self.sock = sock
        self.record_layer = for_client(session, sock)
        self.connected_host = host
        self.connected_port = port

        if self.collector:
            self.collector.end_hct()

        print(f"Handshake complete. Mode: {session.handshake_mode}")

    def accept(self, *args, **kwargs):
        raise NotImplementedError("TCP client transport cannot accept inbound connections")

    def send_handshake(self, payload: bytes, *, sock: Optional[socket.socket] = None) -> None:
        target = sock or self.sock
        if target is None:
            raise RuntimeError("TCP transport is not connected")
        header = len(payload).to_bytes(4, "big")
        target.sendall(header + payload)

    def recv_handshake(self, *, sock: Optional[socket.socket] = None) -> bytes:
        target = sock or self.sock
        if target is None:
            raise RuntimeError("TCP transport is not connected")
        header = self._read_n_bytes(target, 4, eof_message="Socket closed during handshake")
        length = int.from_bytes(header, "big")
        return self._read_n_bytes(
            target,
            length,
            eof_message="Socket closed during handshake data read",
        )

    def send_application(self, payload: bytes) -> None:
        if self.record_layer is None:
            raise RuntimeError("No active record layer")
        self.record_layer.send_record(payload)

    def recv_application(self) -> bytes:
        if self.record_layer is None:
            raise RuntimeError("No active record layer")
        return self.record_layer.recv_record()

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        self.record_layer = None
        self.connected_host = None
        self.connected_port = None

    def matches_endpoint(self, host: str, port: int) -> bool:
        return (
            self.sock is not None
            and self.record_layer is not None
            and self.connected_host == host
            and self.connected_port == port
        )

    @staticmethod
    def _read_n_bytes(target: socket.socket, n: int, *, eof_message: str) -> bytes:
        data = b""
        while len(data) < n:
            chunk = target.recv(n - len(data))
            if not chunk:
                raise EOFError(eof_message)
            data += chunk
        return data


class KEMTLSTCPServerConnection(KEMTLSTransport):
    """Server-side TCP transport bound to an accepted socket."""

    def __init__(self, sock: socket.socket):
        super().__init__()
        self.sock = sock
        self.record_layer = None

    def connect(self, *args, **kwargs):
        raise NotImplementedError("TCP server transport does not initiate outbound connections")

    def accept(self, *args, **kwargs):
        return self

    def send_handshake(self, payload: bytes) -> None:
        header = len(payload).to_bytes(4, "big")
        self.sock.sendall(header + payload)

    def recv_handshake(self) -> bytes:
        header = self._read_n_bytes(4, eof_message="Socket closed during handshake")
        length = int.from_bytes(header, "big")
        return self._read_n_bytes(length, eof_message="Socket closed during handshake data read")

    def send_application(self, payload: bytes) -> None:
        if self.record_layer is None:
            raise RuntimeError("No active record layer")
        self.record_layer.send_record(payload)

    def recv_application(self) -> bytes:
        if self.record_layer is None:
            raise RuntimeError("No active record layer")
        return self.record_layer.recv_record()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass
        self.record_layer = None
        self.session = None

    def complete_handshake(
        self,
        *,
        server_identity: str,
        server_lt_sk: bytes,
        cert: Optional[Dict[str, Any]] = None,
        pdk_key_id: Optional[str] = None,
        collector: Optional[Any] = None,
    ):
        handshake = ServerHandshake(
            server_identity,
            server_lt_sk,
            cert,
            pdk_key_id,
            collector=collector,
        )

        client_hello = self.recv_handshake()
        server_hello = handshake.process_client_hello(client_hello)
        self.send_handshake(server_hello)

        client_key_exchange = self.recv_handshake()
        server_finished = handshake.process_client_key_exchange(client_key_exchange)
        self.send_handshake(server_finished)

        client_finished = self.recv_handshake()
        session = handshake.verify_client_finished(client_finished)
        session.transport = "tcp"
        self.session = session
        self.record_layer = for_server(session, self.sock)
        return session

    def _read_n_bytes(self, n: int, *, eof_message: str) -> bytes:
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise EOFError(eof_message)
            data += chunk
        return data


def build_http_request(
    host: str,
    method: str,
    path: str,
    headers: Optional[Dict[str, str]] = None,
    body: bytes = b"",
    keep_alive: bool = False,
) -> bytes:
    header_lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    for key, value in (headers or {}).items():
        if key.lower() == "host":
            continue
        header_lines.append(f"{key}: {value}")
    if body and not any(key.lower() == "content-length" for key in (headers or {})):
        header_lines.append(f"Content-Length: {len(body)}")
    header_lines.append("Connection: keep-alive" if keep_alive else "Connection: close")
    return ("\r\n".join(header_lines) + "\r\n\r\n").encode("ascii") + body


def request_over_transport(
    transport: KEMTLSTCPClientTransport,
    *,
    host: str,
    port: int,
    method: str,
    path: str,
    headers: Optional[Dict[str, str]] = None,
    body: bytes = b"",
    keep_alive: bool = False,
    header_mutator: Optional[Callable[[Dict[str, str], Any], None]] = None,
) -> Tuple[bytes, Any]:
    reuse = keep_alive and transport.matches_endpoint(host, port)
    if not reuse:
        transport.close()
        transport.connect(host, port)

    effective_headers = dict(headers or {})
    if header_mutator is not None:
        header_mutator(effective_headers, transport.session)

    request_bytes = build_http_request(
        host,
        method,
        path,
        headers=effective_headers,
        body=body,
        keep_alive=keep_alive,
    )
    transport.send_application(request_bytes)
    response = transport.recv_application()
    return response, transport.session
