"""
KEMTLS Protocol Implementation

This module implements the KEMTLS (Key Encapsulation Mechanism Transport Layer Security)
protocol, which replaces traditional TLS certificate-based authentication with
KEM-based authentication.

Key Innovation: Server authenticates by successfully decapsulating a ciphertext,
NOT by providing a digital signature.

Modules:
    - handshake: KEMTLS handshake protocol
    - channel: Encrypted communication channel
    - session: Session management
"""

from .handshake import KEMTLSHandshake
from .channel import KEMTLSChannel
from .session import KEMTLSSession

__all__ = [
    "KEMTLSHandshake",
    "KEMTLSChannel",
    "KEMTLSSession",
]
