#!/usr/bin/env python3
"""Quick monitor-mode sniff test for 802.11 packets."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sniff monitor-mode packets for validation")
    parser.add_argument("--interface", default="wlp2s0mon")
    parser.add_argument("--count", type=int, default=40, help="Number of packets to capture")
    parser.add_argument("--timeout", type=int, default=30, help="Capture timeout in seconds")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        from scapy.all import sniff  # type: ignore[import-not-found]
        from scapy.layers.dot11 import Dot11  # type: ignore[import-not-found]
    except ImportError:
        print("Scapy is not installed. Run: pip install -r requirements.txt", file=sys.stderr)
        return 1
    print(
        f"Sniffing on {args.interface} | packet limit={args.count}, timeout={args.timeout}s"
    )

    def print_packet(pkt: object) -> None:
        if not pkt.haslayer(Dot11):  # type: ignore[union-attr]
            return
        dot11 = pkt.getlayer(Dot11)  # type: ignore[union-attr]
        subtype = getattr(dot11, "subtype", "n/a")
        src = getattr(dot11, "addr2", "unknown")
        dst = getattr(dot11, "addr1", "unknown")
        bssid = getattr(dot11, "addr3", "unknown")
        print(f"subtype={subtype:<3} src={src} dst={dst} bssid={bssid}")

    sniff(
        iface=args.interface,
        prn=print_packet,
        count=args.count,
        timeout=args.timeout,
        store=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
