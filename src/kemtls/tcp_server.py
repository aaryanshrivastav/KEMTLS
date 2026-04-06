"""
KEMTLS TCP Server

A multi-threaded TCP server that handles KEMTLS handshakes, 
transitions to an encrypted record layer, and bridges to a Flask app.
"""

import socket
import signal
import threading
import traceback
from typing import Dict, Any, Optional
from flask import Flask
from .handshake import ServerHandshake
from .record_layer import for_server
from ._http_bridge import call_flask_app, parse_http_request


class KEMTLSTCPServer:
    """
    KEMTLS TCP Server implementation.
    """
    
    def __init__(
        self,
        app: Flask,
        server_identity: str,
        server_lt_sk: bytes,
        cert: Optional[Dict[str, Any]] = None,
        pdk_key_id: Optional[str] = None,
        host: str = "0.0.0.0",
        port: int = 4433
    ):
        self.app = app
        self.server_identity = server_identity
        self.server_lt_sk = server_lt_sk
        self.cert = cert
        self.pdk_key_id = pdk_key_id
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(1.0)
        self._stop_event = threading.Event()

    def stop(self):
        """Request server shutdown and close the listening socket."""
        self._stop_event.set()
        try:
            self.sock.close()
        except OSError:
            pass

    def start(self):
        """Start the server loop."""
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        print(f"KEMTLS Server listening on {self.host}:{self.port}")
        previous_sigint = None
        previous_sigterm = None

        if threading.current_thread() is threading.main_thread():
            def _handle_signal(signum, _frame):
                print(f"Signal {signum} received. Stopping server...")
                self.stop()

            previous_sigint = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, _handle_signal)

            if hasattr(signal, "SIGTERM"):
                previous_sigterm = signal.getsignal(signal.SIGTERM)
                signal.signal(signal.SIGTERM, _handle_signal)
        
        try:
            while not self._stop_event.is_set():
                try:
                    client_sock, addr = self.sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop_event.is_set():
                        break
                    raise

                print(f"Accepted connection from {addr}")
                t = threading.Thread(target=self._handle_client, args=(client_sock,))
                t.daemon = True
                t.start()
        except KeyboardInterrupt:
            print("Server stopping...")
            self.stop()
        finally:
            self.stop()
            if previous_sigint is not None:
                signal.signal(signal.SIGINT, previous_sigint)
            if previous_sigterm is not None and hasattr(signal, "SIGTERM"):
                signal.signal(signal.SIGTERM, previous_sigterm)

    def _handle_client(self, client_sock: socket.socket):
        """Individual client connection handler."""
        try:
            # 1. Perform Handshake
            handshake = ServerHandshake(
                self.server_identity,
                self.server_lt_sk,
                self.cert,
                self.pdk_key_id
            )
            
            # Message 1: ClientHello
            ch_bytes = self._read_msg(client_sock)
            sh_bytes = handshake.process_client_hello(ch_bytes)
            self._send_msg(client_sock, sh_bytes)
            
            # Message 2: ClientKeyExchange
            cke_bytes = self._read_msg(client_sock)
            sf_bytes = handshake.process_client_key_exchange(cke_bytes)
            self._send_msg(client_sock, sf_bytes)
            
            # Message 3: ClientFinished
            cf_bytes = self._read_msg(client_sock)
            session = handshake.verify_client_finished(cf_bytes)
            
            print(f"Handshake complete. Mode: {session.handshake_mode}")
            
            # 2. Record Layer
            record_layer = for_server(session, client_sock)

            # 3. Process one or more encrypted HTTP requests on same session.
            while True:
                try:
                    raw_request = record_layer.recv_record()
                except EOFError:
                    # Normal disconnect path (e.g., client closes keep-alive socket).
                    break
                req = parse_http_request(raw_request)
                response_bytes = call_flask_app(self.app, session, raw_request)
                record_layer.send_record(response_bytes)

                connection_header = str(req.get("headers", {}).get("connection", "")).lower()
                if connection_header == "close":
                    break
            
        except EOFError:
            # Treat peer close as a clean shutdown for this connection.
            pass
        except Exception as e:
            print(f"Error handling client: {e!r}")
            traceback.print_exc()
        finally:
            client_sock.close()

    def _read_msg(self, sock: socket.socket) -> bytes:
        """Simple length-prefix reader for handshake messages."""
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
        """Simple length-prefix sender for handshake messages."""
        header = len(msg).to_bytes(4, "big")
        sock.sendall(header + msg)
