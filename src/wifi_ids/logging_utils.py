"""Logging helpers for wireless IDS events."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import TextIO

from .models import DetectionEvent


class EventLogger:
    """Thread-safe log writer for human-readable and JSONL outputs."""

    def __init__(self, text_log_path: str, window_seconds: int, jsonl_path: str | None = None) -> None:
        self._window_seconds = window_seconds
        self._lock = threading.Lock()

        text_path = Path(text_log_path)
        text_path.parent.mkdir(parents=True, exist_ok=True)
        self._text_file: TextIO = text_path.open("a", encoding="utf-8")

        self._json_file: TextIO | None = None
        if jsonl_path:
            json_path = Path(jsonl_path)
            json_path.parent.mkdir(parents=True, exist_ok=True)
            self._json_file = json_path.open("a", encoding="utf-8")

    def log(self, event: DetectionEvent) -> None:
        """Write event to configured logs."""
        with self._lock:
            self._text_file.write(event.to_log_block(self._window_seconds))
            self._text_file.write("\n")
            self._text_file.flush()

            if self._json_file:
                payload = {
                    "timestamp": event.timestamp.isoformat(),
                    "level": event.level,
                    "frame_type": event.frame_type,
                    "attacker_mac": event.attacker_mac,
                    "client_mac": event.client_mac,
                    "bssid": event.bssid,
                    "attacker_window_count": event.attacker_window_count,
                    "pair_window_count": event.pair_window_count,
                    "affected_clients": event.affected_clients,
                    "interface": event.interface,
                }
                self._json_file.write(json.dumps(payload, ensure_ascii=True))
                self._json_file.write("\n")
                self._json_file.flush()

    def close(self) -> None:
        with self._lock:
            self._text_file.close()
            if self._json_file:
                self._json_file.close()
