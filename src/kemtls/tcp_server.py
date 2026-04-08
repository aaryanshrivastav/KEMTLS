"""
KEMTLS TCP Server

TCP server plumbing for KEMTLS + HTTP bridge integration.
"""

from __future__ import annotations

import signal
import socket
import threading
import traceback
from typing import Any, Dict, Optional

from flask import Flask

from .tcp_transport import KEMTLSTCPServerConnection, handle_application_session


class KEMTLSTCPServer:
    """
    TCP server wrapper for KEMTLS transport sessions.
    """

    def __init__(
        self,
        app: Flask,
        server_identity: str,
        server_lt_sk: bytes,
        cert: Optional[Dict[str, Any]] = None,
        pdk_key_id: Optional[str] = None,
        host: str = "0.0.0.0",
        port: int = 4433,
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
        """Start the TCP accept loop."""
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
                thread = threading.Thread(target=self._handle_client, args=(client_sock,))
                thread.daemon = True
                thread.start()
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
        """Handle a single accepted TCP client socket."""
        connection = KEMTLSTCPServerConnection(client_sock)
        try:
            collector = None
            if hasattr(self, "get_collector") and callable(self.get_collector):
                collector = self.get_collector()

            if collector:
                collector.start_hct()

            session = connection.complete_handshake(
                server_identity=self.server_identity,
                server_lt_sk=self.server_lt_sk,
                cert=self.cert,
                pdk_key_id=self.pdk_key_id,
                collector=collector,
            )

            if collector:
                collector.end_hct()
                if hasattr(self, "on_handshake_complete") and callable(self.on_handshake_complete):
                    self.on_handshake_complete(collector.get_metrics())

            print(f"Handshake complete. Mode: {session.handshake_mode}")
            handle_application_session(self.app, connection)
        except EOFError:
            pass
        except Exception as e:
            print(f"Error handling client: {e!r}")
            traceback.print_exc()
        finally:
            connection.close()
