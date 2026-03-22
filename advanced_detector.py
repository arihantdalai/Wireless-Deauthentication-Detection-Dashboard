#!/usr/bin/env python3
"""Advanced console detector with periodic attacker summary."""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path
from threading import Event, Lock, Thread
from time import sleep

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from wifi_ids import DetectorConfig, EventLogger, WirelessIDSDetector
from wifi_ids.models import DetectionEvent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Advanced wireless IDS console mode")
    parser.add_argument("--interface", default="wlp2s0mon")
    parser.add_argument("--threshold", type=int, default=3)
    parser.add_argument("--window", type=int, default=10)
    parser.add_argument("--summary-every", type=int, default=15, help="Summary print interval in seconds")
    parser.add_argument("--deauth-only", action="store_true")
    parser.add_argument("--log-file", default="logs/wifi_ids_events.log")
    parser.add_argument("--json-log", default="logs/wifi_ids_events.jsonl")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.threshold < 1 or args.window < 1 or args.summary_every < 1:
        print("Error: threshold/window/summary-every must be >= 1", file=sys.stderr)
        return 2

    config = DetectorConfig(
        interface=args.interface,
        threshold=args.threshold,
        window_seconds=args.window,
        include_disassoc=not args.deauth_only,
    )
    logger = EventLogger(args.log_file, window_seconds=args.window, jsonl_path=args.json_log)
    detector = WirelessIDSDetector(config=config)

    lock = Lock()
    stop_event = Event()
    attacker_counter: Counter[str] = Counter()
    client_counter: Counter[str] = Counter()
    alert_counter = 0
    event_counter = 0

    def on_event(event: DetectionEvent) -> None:
        nonlocal alert_counter, event_counter
        logger.log(event)
        with lock:
            event_counter += 1
            attacker_counter[event.attacker_mac] += 1
            client_counter[event.client_mac] += 1
            if event.level == "ALERT":
                alert_counter += 1
                print(
                    f"[{event.timestamp_display()}] ALERT "
                    f"{event.attacker_mac} -> {event.client_mac} "
                    f"(window={event.attacker_window_count}, affected={event.affected_clients})"
                )

    detector.event_callback = on_event

    def summary_worker() -> None:
        while not stop_event.wait(args.summary_every):
            with lock:
                top_attackers = attacker_counter.most_common(3)
                top_clients = client_counter.most_common(3)
                events = event_counter
                alerts = alert_counter

            print("\n=== Wireless IDS Summary ===")
            print(f"Total Events: {events}")
            print(f"Total Alerts: {alerts}")
            if top_attackers:
                print("Top Attackers:")
                for mac, count in top_attackers:
                    print(f"  {mac}: {count}")
            else:
                print("Top Attackers: n/a")
            if top_clients:
                print("Most Targeted Clients:")
                for mac, count in top_clients:
                    print(f"  {mac}: {count}")
            else:
                print("Most Targeted Clients: n/a")
            print("============================\n")

    summary_thread = Thread(target=summary_worker, daemon=True)
    summary_thread.start()

    print(f"Starting advanced detector on interface {args.interface}")
    print(f"Alert threshold: {args.threshold} events in {args.window} seconds")
    print("Press Ctrl+C to stop\n")

    try:
        detector.start()
        while detector.running:
            sleep(0.25)
    except KeyboardInterrupt:
        print("\nStopping advanced detector...")
    finally:
        stop_event.set()
        detector.stop()
        logger.close()
        summary_thread.join(timeout=1.0)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
