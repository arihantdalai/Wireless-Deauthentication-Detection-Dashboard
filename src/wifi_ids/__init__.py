"""Wireless IDS package."""

from .detector import DetectorConfig, WirelessIDSDetector, lock_channel
from .logging_utils import EventLogger
from .models import DetectionEvent

__all__ = [
    "DetectionEvent",
    "DetectorConfig",
    "EventLogger",
    "WirelessIDSDetector",
    "lock_channel",
]
