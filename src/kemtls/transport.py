"""Abstract transport contract for KEMTLS handshakes and application payloads."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from .session import KEMTLSSession


class KEMTLSTransport(ABC):
    """Common interface shared by transport implementations."""

    def __init__(self):
        self.session: Optional[KEMTLSSession] = None

    @abstractmethod
    def connect(self, *args, **kwargs):
        """Open or establish an outbound transport connection."""

    @abstractmethod
    def accept(self, *args, **kwargs):
        """Accept an inbound transport connection."""

    @abstractmethod
    def send_handshake(self, payload: bytes) -> None:
        """Send a handshake message."""

    @abstractmethod
    def recv_handshake(self) -> bytes:
        """Receive a handshake message."""

    @abstractmethod
    def send_application(self, payload: bytes) -> None:
        """Send protected application data."""

    @abstractmethod
    def recv_application(self) -> bytes:
        """Receive protected application data."""

    @abstractmethod
    def close(self) -> None:
        """Close any underlying transport resources."""
