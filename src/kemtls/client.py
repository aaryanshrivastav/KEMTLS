"""
KEMTLS Socket Client

A socket-based client that performs a KEMTLS handshake and 
sends an encrypted HTTP request over a record layer.
"""

import socket
from typing import Dict, Any, Optional, Tuple
from .handshake import ClientHandshake
from .record_layer import for_client
from .pdk import PDKTrustStore


class KEMTLSClient:
    """
    KEMTLS client for making secure requests.
    """
    
    def __init__(
        self,
        expected_identity: str,
        ca_pk: Optional[bytes] = None,
        pdk_store: Optional[PDKTrustStore] = None,
        mode: str = "auto"
    ):
        self.expected_identity = expected_identity
        self.ca_pk = ca_pk
        self.pdk_store = pdk_store
        self.mode = mode
        self.session = None
        self.sock: Optional[socket.socket] = None
        self.record_layer = None
        self.connected_host: Optional[str] = None
        self.connected_port: Optional[int] = None

    def close(self):
        """Close any active KEMTLS transport connection."""
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        self.record_layer = None
        self.connected_host = None
        self.connected_port = None

    def _open_connection(self, host: str, port: int) -> None:
        """Open socket and complete a full KEMTLS handshake."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))

        # 1. Perform Handshake
        handshake = ClientHandshake(
            self.expected_identity,
            self.ca_pk,
            self.pdk_store,
            self.mode,
        )

        # Message 1: ClientHello
        ch_bytes = handshake.client_hello()
        self._send_msg(sock, ch_bytes)

        # Message 2: ServerHello
        sh_bytes = self._read_msg(sock)
        cke_bytes, session = handshake.process_server_hello(sh_bytes)
        self._send_msg(sock, cke_bytes)

        # Message 3: ServerFinished
        sf_bytes = self._read_msg(sock)
        handshake.process_server_finished(sf_bytes, session)

        # Message 4: ClientFinished
        cf_bytes = handshake.client_finished()
        self._send_msg(sock, cf_bytes)

        self.session = session
        self.sock = sock
        self.record_layer = for_client(session, sock)
        self.connected_host = host
        self.connected_port = port
        print(f"Handshake complete. Mode: {session.handshake_mode}")

    def _request_over_active_connection(
        self,
        host: str,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        body: bytes = b"",
        keep_alive: bool = False,
    ) -> bytes:
        if self.record_layer is None:
            raise RuntimeError("No active record layer")

        header_lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
        for key, value in (headers or {}).items():
            if key.lower() == "host":
                continue
            header_lines.append(f"{key}: {value}")
        if body and not any(k.lower() == "content-length" for k in (headers or {})):
            header_lines.append(f"Content-Length: {len(body)}")
        header_lines.append("Connection: keep-alive" if keep_alive else "Connection: close")

        http_req = ("\r\n".join(header_lines) + "\r\n\r\n").encode("ascii") + body
        self.record_layer.send_record(http_req)
        return self.record_layer.recv_record()

    def request(
        self,
        host: str,
        port: int,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        body: bytes = b"",
        keep_alive: bool = False,
    ) -> Tuple[bytes, Any]:
        """
        Connect to a server, perform handshake, and send an encrypted request.
        """
        try:
            reuse = (
                keep_alive
                and self.sock is not None
                and self.record_layer is not None
                and self.connected_host == host
                and self.connected_port == port
            )
            if not reuse:
                self.close()
                self._open_connection(host, port)

            response = self._request_over_active_connection(
                host,
                method,
                path,
                headers=headers,
                body=body,
                keep_alive=keep_alive,
            )
            return response, self.session
            
        except Exception as e:
            print(f"Error in client: {e}")
            self.close()
            raise
        finally:
            if not keep_alive:
                self.close()

    def _read_msg(self, sock: socket.socket) -> bytes:
        """Handshake length-prefix reader."""
        header = sock.recv(4)
        if not header:
            raise EOFError("Socket closed during handshake")
        length = int.from_bytes(header, "big")
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                raise EOFError("Socket closed during handshake data read")
            data += chunk
        return data

    def _send_msg(self, sock: socket.socket, msg: bytes):
        """Handshake length-prefix sender."""
        header = len(msg).to_bytes(4, "big")
        sock.sendall(header + msg)
