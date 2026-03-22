"""Wireless deauthentication/disassociation detector engine."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from subprocess import CalledProcessError, run
from threading import Lock
from time import sleep, time
from typing import Callable, Deque, Dict

from .models import DetectionEvent

try:
    from scapy.all import AsyncSniffer  # type: ignore[import-not-found]
    from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - runtime dependency on Linux host
    AsyncSniffer = None
    Dot11 = Dot11Deauth = Dot11Disas = None


BROADCAST_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}


@dataclass(slots=True)
class DetectorConfig:
    interface: str = "wlp2s0mon"
    threshold: int = 3
    window_seconds: int = 10
    include_disassoc: bool = True
    ignore_broadcast_client: bool = False


def _normalize_mac(value: str | None) -> str:
    if not value:
        return "unknown"
    return value.lower()


class WirelessIDSDetector:
    """Sniffs management frames and emits detection events."""

    def __init__(
        self,
        config: DetectorConfig,
        event_callback: Callable[[DetectionEvent], None] | None = None,
    ) -> None:
        self.config = config
        self.event_callback = event_callback

        self._sniffer = None
        self._lock = Lock()
        self._running = False

        self._attacker_activity: Dict[str, Deque[float]] = defaultdict(deque)
        self._pair_activity: Dict[tuple[str, str], Deque[float]] = defaultdict(deque)
        self._attacker_clients: Dict[str, Dict[str, float]] = defaultdict(dict)

        self.total_events = 0
        self.total_alerts = 0

    @property
    def running(self) -> bool:
        return self._running

    def start(self) -> None:
        """Start asynchronous sniffing."""
        if AsyncSniffer is None:
            raise RuntimeError(
                "Scapy is not installed. Install dependencies with: pip install -r requirements.txt"
            )

        with self._lock:
            if self._running:
                return
            self._sniffer = AsyncSniffer(
                iface=self.config.interface,
                prn=self._handle_packet,
                store=False,
            )
            self._sniffer.start()
            self._running = True

    def stop(self) -> None:
        """Stop sniffing and release resources."""
        with self._lock:
            if not self._running:
                return
            if self._sniffer is not None:
                self._sniffer.stop()
            self._sniffer = None
            self._running = False

    def run_forever(self, poll_interval: float = 0.25) -> None:
        """Run detector loop until keyboard interruption."""
        self.start()
        try:
            while self.running:
                sleep(poll_interval)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def _handle_packet(self, packet: object) -> None:
        event = self.process_packet(packet)
        if event is None:
            return
        if self.event_callback:
            self.event_callback(event)

    def process_packet(self, packet: object) -> DetectionEvent | None:
        """Process one scapy packet and produce an event if relevant."""
        if Dot11 is None:
            return None
        if not packet or not packet.haslayer(Dot11):  # type: ignore[union-attr]
            return None

        frame_type = None
        if packet.haslayer(Dot11Deauth):  # type: ignore[union-attr]
            frame_type = "deauthentication"
        elif self.config.include_disassoc and packet.haslayer(Dot11Disas):  # type: ignore[union-attr]
            frame_type = "disassociation"

        if frame_type is None:
            return None

        dot11 = packet.getlayer(Dot11)  # type: ignore[union-attr]
        attacker = _normalize_mac(getattr(dot11, "addr2", None))
        client = _normalize_mac(getattr(dot11, "addr1", None))
        bssid = _normalize_mac(getattr(dot11, "addr3", None))

        if self.config.ignore_broadcast_client and client in BROADCAST_MACS:
            return None

        now_epoch = time()
        now_dt = datetime.now()
        window = self.config.window_seconds

        attacker_queue = self._attacker_activity[attacker]
        attacker_queue.append(now_epoch)
        self._drop_old(attacker_queue, now_epoch, window)

        pair_key = (attacker, client)
        pair_queue = self._pair_activity[pair_key]
        pair_queue.append(now_epoch)
        self._drop_old(pair_queue, now_epoch, window)

        clients = self._attacker_clients[attacker]
        clients[client] = now_epoch
        stale_clients = [
            client_mac
            for client_mac, last_seen in clients.items()
            if now_epoch - last_seen > window
        ]
        for client_mac in stale_clients:
            del clients[client_mac]

        attacker_count = len(attacker_queue)
        pair_count = len(pair_queue)
        affected_clients = len(clients)
        level = "ALERT" if attacker_count >= self.config.threshold else "EVENT"

        self.total_events += 1
        if level == "ALERT":
            self.total_alerts += 1

        return DetectionEvent(
            timestamp=now_dt,
            level=level,
            frame_type=frame_type,
            attacker_mac=attacker,
            client_mac=client,
            bssid=bssid,
            attacker_window_count=attacker_count,
            pair_window_count=pair_count,
            affected_clients=affected_clients,
            interface=self.config.interface,
        )

    @staticmethod
    def _drop_old(samples: Deque[float], now_epoch: float, window_seconds: int) -> None:
        while samples and now_epoch - samples[0] > window_seconds:
            samples.popleft()


def lock_channel(interface: str, channel: int) -> None:
    """Optional helper to lock monitor interface on a channel."""
    commands = [
        ["ip", "link", "set", interface, "down"],
        ["iw", "dev", interface, "set", "channel", str(channel)],
        ["ip", "link", "set", interface, "up"],
    ]
    for cmd in commands:
        result = run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip()
            raise CalledProcessError(result.returncode, cmd, output=result.stdout, stderr=stderr)
