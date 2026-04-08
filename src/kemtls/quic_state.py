"""QUIC-style connection state for the future UDP transport path."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple


PeerAddress = Tuple[str, int]


@dataclass
class RetransmissionEntry:
    packet_number: int
    deadline: float
    attempts: int = 0


@dataclass
class QUICConnectionState:
    connection_id: bytes
    peer_address: Optional[PeerAddress] = None
    send_packet_number: int = 0
    recv_packet_number: int = -1
    acked_packets: Set[int] = field(default_factory=set)
    received_packets: Set[int] = field(default_factory=set)
    pending_acks: Set[int] = field(default_factory=set)
    retransmissions: Dict[int, RetransmissionEntry] = field(default_factory=dict)
    handshake_epoch: int = 0
    close_state: str = "open"

    def next_packet_number(self) -> int:
        packet_number = self.send_packet_number
        self.send_packet_number += 1
        return packet_number

    def note_received_packet(self, packet_number: int) -> None:
        if not isinstance(packet_number, int):
            raise TypeError("packet_number must be an integer")
        if packet_number < 0:
            raise ValueError("packet_number must be non-negative")

        self.received_packets.add(packet_number)
        self.pending_acks.add(packet_number)
        if packet_number > self.recv_packet_number:
            self.recv_packet_number = packet_number

    def acknowledge_packet(self, packet_number: int) -> bool:
        if packet_number in self.retransmissions:
            del self.retransmissions[packet_number]
        already_acked = packet_number in self.acked_packets
        self.acked_packets.add(packet_number)
        return not already_acked

    def schedule_retransmission(self, packet_number: int, deadline: float) -> None:
        if not isinstance(packet_number, int):
            raise TypeError("packet_number must be an integer")
        if packet_number < 0:
            raise ValueError("packet_number must be non-negative")
        if not isinstance(deadline, (int, float)):
            raise TypeError("deadline must be numeric")

        previous = self.retransmissions.get(packet_number)
        attempts = 0 if previous is None else previous.attempts + 1
        self.retransmissions[packet_number] = RetransmissionEntry(
            packet_number=packet_number,
            deadline=float(deadline),
            attempts=attempts,
        )

    def expired_retransmissions(self, now: float) -> list[RetransmissionEntry]:
        if not isinstance(now, (int, float)):
            raise TypeError("now must be numeric")
        return [
            entry
            for entry in self.retransmissions.values()
            if entry.deadline <= float(now)
        ]

    def advance_handshake_epoch(self) -> int:
        self.handshake_epoch += 1
        return self.handshake_epoch

    def mark_closed(self) -> None:
        self.close_state = "closed"


__all__ = ["PeerAddress", "QUICConnectionState", "RetransmissionEntry"]
