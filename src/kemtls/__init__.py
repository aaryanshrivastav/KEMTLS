"""
KEMTLS Protocol Implementation

This module implements the KEMTLS (Key Encapsulation Mechanism Transport Layer Security)
protocol, which replaces traditional TLS certificate-based authentication with
KEM-based authentication.

Key Innovation: Server authenticates by successfully decapsulating a ciphertext,
NOT by providing a digital signature.

Modules:
    - handshake: KEMTLS handshake protocol state machines
    - record_layer: Encrypted communication record layer
    - session: Session state model
    - exporter: Session binding/exporter helpers
    - tcp_server: TCP server for KEMTLS + HTTP bridge
    - client: Socket-based KEMTLS client
"""

from .handshake import ClientHandshake, ServerHandshake, KEMTLSHandshake
from .channel import KEMTLSChannel
from .record_layer import (
    AEADPacketProtection,
    KEMTLSRecordLayer,
    for_client,
    for_server,
    frame_tcp_record,
    parse_tcp_record,
    protect,
    unprotect,
)
from .session import KEMTLSSession
from .exporter import (
    derive_exporter_secret,
    derive_session_binding_id,
    derive_refresh_binding_id,
)
from .client import KEMTLSClient
from .transport import KEMTLSTransport
from .tcp_transport import KEMTLSTCPClientTransport

# Optional dependency: Flask is only required for TCP server integration.
try:
    from .tcp_server import KEMTLSTCPServer
except ModuleNotFoundError:
    KEMTLSTCPServer = None

__all__ = [
    "ClientHandshake",
    "ServerHandshake",
    "KEMTLSHandshake",
    "KEMTLSChannel",
    "AEADPacketProtection",
    "KEMTLSRecordLayer",
    "for_client",
    "for_server",
    "protect",
    "unprotect",
    "frame_tcp_record",
    "parse_tcp_record",
    "KEMTLSSession",
    "derive_exporter_secret",
    "derive_session_binding_id",
    "derive_refresh_binding_id",
    "KEMTLSClient",
    "KEMTLSTransport",
    "KEMTLSTCPClientTransport",
]

if KEMTLSTCPServer is not None:
    __all__.append("KEMTLSTCPServer")
