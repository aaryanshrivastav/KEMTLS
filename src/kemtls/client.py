"""
KEMTLS client facade.

Preserves the existing request API while selecting an underlying transport
implementation internally.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Tuple

from .pdk import PDKTrustStore
from .tcp_transport import KEMTLSTCPClientTransport, request_over_transport


class KEMTLSClient:
    """
    KEMTLS client for making secure requests.
    """

    def __init__(
        self,
        expected_identity: str,
        ca_pk: Optional[bytes] = None,
        pdk_store: Optional[PDKTrustStore] = None,
        mode: str = "auto",
        collector: Optional[Any] = None,
        transport: str = "tcp",
    ):
        self.expected_identity = expected_identity
        self.ca_pk = ca_pk
        self.pdk_store = pdk_store
        self.mode = mode
        self.collector = collector
        self.transport_name = transport
        self.transport = self._create_transport(transport)
        self.session = None
        self.sock = None
        self.record_layer = None
        self.connected_host: Optional[str] = None
        self.connected_port: Optional[int] = None

    def _create_transport(self, transport: str):
        if transport == "tcp":
            return KEMTLSTCPClientTransport(
                expected_identity=self.expected_identity,
                ca_pk=self.ca_pk,
                pdk_store=self.pdk_store,
                mode=self.mode,
                collector=self.collector,
            )
        raise ValueError(f"Unsupported transport: {transport}")

    def _sync_transport_config(self) -> None:
        self.transport.expected_identity = self.expected_identity
        self.transport.ca_pk = self.ca_pk
        self.transport.pdk_store = self.pdk_store
        self.transport.mode = self.mode
        self.transport.collector = self.collector

    def _sync_transport_state(self) -> None:
        self.session = self.transport.session
        self.sock = getattr(self.transport, "sock", None)
        self.record_layer = getattr(self.transport, "record_layer", None)
        self.connected_host = getattr(self.transport, "connected_host", None)
        self.connected_port = getattr(self.transport, "connected_port", None)

    def close(self):
        """Close any active KEMTLS transport connection."""
        self.transport.close()
        self._sync_transport_state()

    def request(
        self,
        host: str,
        port: int,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        body: bytes = b"",
        keep_alive: bool = False,
        header_mutator: Optional[Callable[[Dict[str, str], Any], None]] = None,
    ) -> Tuple[bytes, Any]:
        """
        Connect to a server, perform handshake, and send an encrypted request.
        """
        try:
            self._sync_transport_config()
            response, session = request_over_transport(
                self.transport,
                host=host,
                port=port,
                method=method,
                path=path,
                headers=headers,
                body=body,
                keep_alive=keep_alive,
                header_mutator=header_mutator,
            )
            self._sync_transport_state()
            return response, session
        except Exception as e:
            print(f"Error in client: {e}")
            self.close()
            raise
        finally:
            if not keep_alive:
                self.close()
