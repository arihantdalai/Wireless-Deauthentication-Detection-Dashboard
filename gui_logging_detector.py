#!/usr/bin/env python3
"""Launch Wireless IDS GUI with logging enabled."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from wifi_ids import DetectorConfig, EventLogger, WirelessIDSDetector, lock_channel


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Wireless deauthentication detection dashboard")
    parser.add_argument("--interface", default="wlp2s0mon", help="Monitor mode interface (default: wlp2s0mon)")
    parser.add_argument("--threshold", type=int, default=3, help="Alert threshold inside time window")
    parser.add_argument("--window", type=int, default=10, help="Sliding time window in seconds")
    parser.add_argument("--deauth-only", action="store_true", help="Ignore disassociation frames")
    parser.add_argument(
        "--ignore-broadcast-client",
        action="store_true",
        help="Ignore events where target client is broadcast address",
    )
    parser.add_argument("--channel", type=int, help="Optional WiFi channel to lock the interface")
    parser.add_argument(
        "--lock-channel",
        action="store_true",
        help="Apply channel lock sequence (requires sudo and monitor mode)",
    )
    parser.add_argument("--log-file", default="logs/wifi_ids_events.log", help="Path for text event log")
    parser.add_argument("--json-log", default="logs/wifi_ids_events.jsonl", help="Path for JSONL event log")
    parser.add_argument("--demo", action="store_true", help="Run dashboard with synthetic events")
    parser.add_argument("--demo-interval", type=float, default=1.0, help="Synthetic event interval in seconds")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.threshold < 1:
        print("Error: --threshold must be >= 1", file=sys.stderr)
        return 2
    if args.window < 1:
        print("Error: --window must be >= 1", file=sys.stderr)
        return 2

    config = DetectorConfig(
        interface=args.interface,
        threshold=args.threshold,
        window_seconds=args.window,
        include_disassoc=not args.deauth_only,
        ignore_broadcast_client=args.ignore_broadcast_client,
    )
    detector = WirelessIDSDetector(config=config)

    if args.channel and args.lock_channel and not args.demo:
        try:
            lock_channel(args.interface, args.channel)
        except Exception as exc:
            print(f"Warning: unable to lock channel: {exc}", file=sys.stderr)

    logger = EventLogger(args.log_file, window_seconds=args.window, jsonl_path=args.json_log)
    try:
        from wifi_ids.gui import WirelessIDSDashboard
    except ModuleNotFoundError as exc:
        print(
            f"Missing dependency: {exc}. Install dependencies with: pip install -r requirements.txt",
            file=sys.stderr,
        )
        logger.close()
        return 1

    dashboard = WirelessIDSDashboard(detector=detector, logger=logger)
    dashboard.start_capture(demo_mode=args.demo, demo_interval=args.demo_interval)
    dashboard.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
