"""Data models for wireless IDS events."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class DetectionEvent:
    """Represents one deauthentication/disassociation observation."""

    timestamp: datetime
    level: str
    frame_type: str
    attacker_mac: str
    client_mac: str
    bssid: str
    attacker_window_count: int
    pair_window_count: int
    affected_clients: int
    interface: str

    def timestamp_display(self) -> str:
        """Human-readable local timestamp."""
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S")

    def to_log_block(self, window_seconds: int) -> str:
        """Render a multiline block compatible with project report examples."""
        return (
            f"[{self.timestamp_display()}] {self.level}\n"
            f"Frame: {self.frame_type}\n"
            f"Attacker: {self.attacker_mac}\n"
            f"Client: {self.client_mac}\n"
            f"BSSID: {self.bssid}\n"
            f"WindowCount(attacker/{window_seconds}s): {self.attacker_window_count}\n"
            f"WindowCount(pair/{window_seconds}s): {self.pair_window_count}\n"
            f"AffectedClients({window_seconds}s): {self.affected_clients}\n"
            f"Interface: {self.interface}\n"
        )
