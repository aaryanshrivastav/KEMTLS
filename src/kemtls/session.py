from dataclasses import dataclass
from typing import Optional


@dataclass
class KEMTLSSession:
    """
    Data container for a KEMTLS session state.
    """
    session_id: str
    peer_identity: str
    handshake_mode: str
    trusted_key_id: Optional[str] = None

    client_app_secret: Optional[bytes] = None
    server_app_secret: Optional[bytes] = None

    client_write_key: Optional[bytes] = None
    client_write_iv: Optional[bytes] = None

    server_write_key: Optional[bytes] = None
    server_write_iv: Optional[bytes] = None

    exporter_secret: Optional[bytes] = None

    session_binding_id: Optional[str] = None
    refresh_binding_id: Optional[str] = None

    transport: Optional[str] = None
    alpn: Optional[str] = None
