#!/usr/bin/env python3
"""Console detector for deauthentication/disassociation frames."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from time import sleep

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from wifi_ids import DetectorConfig, EventLogger, WirelessIDSDetector
from wifi_ids.models import DetectionEvent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Wireless IDS terminal detector")
    parser.add_argument("--interface", default="wlp2s0mon", help="Monitor mode interface")
    parser.add_argument("--threshold", type=int, default=3, help="Alert threshold within the window")
    parser.add_argument("--window", type=int, default=10, help="Sliding window in seconds")
    parser.add_argument("--deauth-only", action="store_true", help="Ignore disassociation frames")
    parser.add_argument("--log-file", default="logs/wifi_ids_events.log", help="Text log output path")
    parser.add_argument("--json-log", default="logs/wifi_ids_events.jsonl", help="JSONL output path")
    parser.add_argument(
        "--print-events",
        action="store_true",
        help="Print all events, not just alerts",
    )
    return parser.parse_args()


def _print_event(event: DetectionEvent) -> None:
    print(f"[{event.timestamp_display()}] {event.level}")
    print(f"Frame   : {event.frame_type}")
    print(f"Attacker: {event.attacker_mac}")
    print(f"Client  : {event.client_mac}")
    print(f"BSSID   : {event.bssid}")
    print(
        "Window  : "
        f"attacker={event.attacker_window_count}, pair={event.pair_window_count}, affected={event.affected_clients}"
    )
    print("-" * 64)


def main() -> int:
    args = parse_args()
    if args.threshold < 1 or args.window < 1:
        print("Error: --threshold and --window must be >= 1", file=sys.stderr)
        return 2

    config = DetectorConfig(
        interface=args.interface,
        threshold=args.threshold,
        window_seconds=args.window,
        include_disassoc=not args.deauth_only,
    )

    logger = EventLogger(args.log_file, window_seconds=args.window, jsonl_path=args.json_log)

    def on_event(event: DetectionEvent) -> None:
        logger.log(event)
        if args.print_events or event.level == "ALERT":
            _print_event(event)

    detector = WirelessIDSDetector(config=config, event_callback=on_event)

    print(f"Starting detector on interface: {args.interface}")
    print(f"Threshold: {args.threshold} events in {args.window} seconds")
    print("Press Ctrl+C to stop\n")

    try:
        detector.start()
        while detector.running:
            sleep(0.25)
    except KeyboardInterrupt:
        print("\nStopping detector...")
    finally:
        detector.stop()
        logger.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
