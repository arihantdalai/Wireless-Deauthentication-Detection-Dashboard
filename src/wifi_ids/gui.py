"""Tkinter + Matplotlib dashboard for wireless IDS events."""

from __future__ import annotations

import random
from collections import deque
from datetime import datetime, timedelta
from queue import Empty, Queue
from threading import Event, Thread
from time import sleep
from typing import Deque, List

import matplotlib.dates as mdates
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from tkinter import StringVar, Tk
from tkinter import ttk

from .detector import WirelessIDSDetector
from .logging_utils import EventLogger
from .models import DetectionEvent


class WirelessIDSDashboard:
    """Desktop dashboard for real-time event monitoring."""

    def __init__(
        self,
        detector: WirelessIDSDetector,
        logger: EventLogger,
        max_rows: int = 250,
    ) -> None:
        self.detector = detector
        self.logger = logger
        self.max_rows = max_rows

        self.root = Tk()
        self.root.title("WiFi IDS Dashboard")
        self.root.geometry("1280x820")

        self.status_var = StringVar(value=f"Interface: {self.detector.config.interface} | Capture: stopped")
        self.attack_var = StringVar(value="Attacks: 0")
        self.events_var = StringVar(value="Events: 0")
        self.last_alert_var = StringVar(value="Last Alert: n/a")

        self.total_events = 0
        self.total_alerts = 0
        self.alert_history: Deque[datetime] = deque(maxlen=3000)

        self.event_queue: Queue[DetectionEvent | Exception] = Queue()
        self.stop_event = Event()
        self.capture_thread: Thread | None = None

        self.figure = Figure(figsize=(10, 3.6), dpi=100)
        self.ax = self.figure.add_subplot(111)

        self._build_layout()

    def _build_layout(self) -> None:
        container = ttk.Frame(self.root, padding=12)
        container.pack(fill="both", expand=True)

        title = ttk.Label(
            container,
            text="Wireless IDS Dashboard",
            font=("Segoe UI", 24, "bold"),
        )
        title.pack(anchor="center", pady=(0, 6))

        status_line = ttk.Label(container, textvariable=self.status_var, font=("Segoe UI", 10))
        status_line.pack(anchor="center", pady=(0, 8))

        stats = ttk.Frame(container)
        stats.pack(fill="x", pady=(0, 8))
        ttk.Label(stats, textvariable=self.attack_var, font=("Segoe UI", 11, "bold")).pack(side="left", padx=8)
        ttk.Label(stats, textvariable=self.events_var, font=("Segoe UI", 11, "bold")).pack(side="left", padx=8)
        ttk.Label(stats, textvariable=self.last_alert_var, font=("Segoe UI", 10)).pack(side="left", padx=8)

        table_frame = ttk.LabelFrame(container, text="Live Disconnect Events", padding=8)
        table_frame.pack(fill="both", expand=True)
        columns = ("time", "level", "frame", "attacker", "client", "count", "affected")
        self.event_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=14)
        self.event_table.heading("time", text="Timestamp")
        self.event_table.heading("level", text="Type")
        self.event_table.heading("frame", text="Frame")
        self.event_table.heading("attacker", text="Attacker MAC")
        self.event_table.heading("client", text="Client MAC")
        self.event_table.heading("count", text="Window Count")
        self.event_table.heading("affected", text="Affected Clients")

        self.event_table.column("time", width=170, anchor="center")
        self.event_table.column("level", width=80, anchor="center")
        self.event_table.column("frame", width=130, anchor="center")
        self.event_table.column("attacker", width=200, anchor="center")
        self.event_table.column("client", width=200, anchor="center")
        self.event_table.column("count", width=110, anchor="center")
        self.event_table.column("affected", width=120, anchor="center")
        self.event_table.pack(fill="both", expand=True, side="left")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.event_table.yview)
        scrollbar.pack(side="right", fill="y")
        self.event_table.configure(yscrollcommand=scrollbar.set)
        self.event_table.tag_configure("ALERT", foreground="#b00020")
        self.event_table.tag_configure("EVENT", foreground="#1f4d87")

        graph_frame = ttk.LabelFrame(container, text="Attack Activity (Last 5 Minutes)", padding=8)
        graph_frame.pack(fill="both", expand=True, pady=(8, 0))
        self.ax.set_title("Alert Count per 10-Second Window")
        self.ax.set_ylabel("Alert Count")
        self.ax.grid(True, alpha=0.35)
        self.canvas = FigureCanvasTkAgg(self.figure, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        self.canvas.draw_idle()

    def submit_event(self, event: DetectionEvent) -> None:
        self.event_queue.put(event)

    def start_capture(self, demo_mode: bool = False, demo_interval: float = 1.0) -> None:
        self.stop_event.clear()
        if demo_mode:
            self.status_var.set("Interface: demo | Capture: running synthetic traffic")
            self.capture_thread = Thread(
                target=self._demo_worker,
                kwargs={"interval": demo_interval},
                daemon=True,
            )
        else:
            self.status_var.set(
                f"Interface: {self.detector.config.interface} | Capture: starting..."
            )
            self.capture_thread = Thread(target=self._capture_worker, daemon=True)
        self.capture_thread.start()
        if not demo_mode:
            self.status_var.set(
                f"Interface: {self.detector.config.interface} | Capture: running"
            )
        self._poll_queue()

    def _capture_worker(self) -> None:
        try:
            self.detector.start()
            while not self.stop_event.is_set():
                sleep(0.25)
        except Exception as exc:  # pragma: no cover - environment dependent
            self.event_queue.put(exc)
        finally:
            self.detector.stop()

    def _demo_worker(self, interval: float = 1.0) -> None:
        attackers = [
            "a4:ce:da:30:d7:13",
            "ec:34:78:8d:11:ce",
            "8c:5d:60:a2:1f:f4",
        ]
        clients = [
            "48:55:5e:03:1d:d2",
            "74:3a:65:af:08:d1",
            "90:9f:33:2c:ea:11",
        ]
        while not self.stop_event.is_set():
            attacker = random.choice(attackers)
            client = random.choice(clients)
            is_alert = random.random() > 0.55
            event = DetectionEvent(
                timestamp=datetime.now(),
                level="ALERT" if is_alert else "EVENT",
                frame_type="deauthentication" if random.random() > 0.3 else "disassociation",
                attacker_mac=attacker,
                client_mac=client,
                bssid=client,
                attacker_window_count=random.randint(1, 8),
                pair_window_count=random.randint(1, 5),
                affected_clients=random.randint(1, 3),
                interface="demo",
            )
            self.event_queue.put(event)
            sleep(max(interval, 0.2))

    def _poll_queue(self) -> None:
        had_updates = False
        while True:
            try:
                item = self.event_queue.get_nowait()
            except Empty:
                break

            had_updates = True
            if isinstance(item, Exception):
                self.status_var.set(f"Capture error: {item}")
                continue

            event = item
            self.logger.log(event)
            self.total_events += 1
            self.events_var.set(f"Events: {self.total_events}")

            if event.level == "ALERT":
                self.total_alerts += 1
                self.attack_var.set(f"Attacks: {self.total_alerts}")
                self.last_alert_var.set(f"Last Alert: {event.timestamp_display()}")
                self.alert_history.append(event.timestamp)

            self.event_table.insert(
                "",
                0,
                values=(
                    event.timestamp_display(),
                    event.level,
                    event.frame_type,
                    event.attacker_mac,
                    event.client_mac,
                    event.attacker_window_count,
                    event.affected_clients,
                ),
                tags=(event.level,),
            )

            children: List[str] = list(self.event_table.get_children())
            if len(children) > self.max_rows:
                self.event_table.delete(children[-1])

        if had_updates:
            self._refresh_graph()
        if not self.stop_event.is_set():
            self.root.after(300, self._poll_queue)

    def _refresh_graph(self) -> None:
        now = datetime.now()
        cutoff = now - timedelta(minutes=5)
        while self.alert_history and self.alert_history[0] < cutoff:
            self.alert_history.popleft()

        bucket_seconds = 10
        bucket_counts = {}
        for ts in self.alert_history:
            rounded = ts.replace(microsecond=0) - timedelta(seconds=ts.second % bucket_seconds)
            bucket_counts[rounded] = bucket_counts.get(rounded, 0) + 1

        xs = sorted(bucket_counts.keys())
        ys = [bucket_counts[t] for t in xs]

        self.ax.clear()
        self.ax.set_title("Alert Count per 10-Second Window")
        self.ax.set_ylabel("Alert Count")
        self.ax.grid(True, alpha=0.35)
        self.ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))

        if xs:
            self.ax.plot(xs, ys, color="#c62828", marker="o", linewidth=1.8)
        else:
            self.ax.plot([now], [0], color="#607d8b", marker="o")

        self.figure.autofmt_xdate(rotation=25)
        self.canvas.draw_idle()

    def run(self) -> None:
        self.root.protocol("WM_DELETE_WINDOW", self._shutdown)
        self.root.mainloop()

    def _shutdown(self) -> None:
        self.stop_event.set()
        self.detector.stop()
        self.logger.close()
        self.root.destroy()
