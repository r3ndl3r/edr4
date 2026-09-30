"""Host resource and network telemetry."""

from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from collections import Counter

import psutil

from collectors.base import BaseCollector
from core.event_bus import EventBus
from core.events import create_event


class SystemCollector(BaseCollector):
    def __init__(
        self,
        event_bus: EventBus,
        stop_event: threading.Event,
        logger: logging.Logger,
        poll_interval: float,
        interface: str,
    ) -> None:
        super().__init__("system", event_bus, stop_event, logger)
        self.poll_interval = poll_interval
        self.interface = interface
        self._previous_net: tuple[float, object] | None = None
        psutil.cpu_percent(interval=None)

    def _system_event(self):
        cpu = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        try:
            load = list(os.getloadavg())
        except (AttributeError, OSError):
            load = []
        return create_event(
            event_type="system_metrics",
            source="system",
            message=f"cpu={cpu:.1f}% mem={memory.percent:.1f}% disk={disk.percent:.1f}%",
            data={
                "cpu_percent": round(cpu, 2),
                "memory_percent": round(memory.percent, 2),
                "memory_available_bytes": memory.available,
                "disk_percent": round(disk.percent, 2),
                "disk_free_bytes": disk.free,
                "load_average": load,
            },
        )

    def _network_counters(self):
        per_interface = psutil.net_io_counters(pernic=True)
        counters = per_interface.get(self.interface)
        interface = self.interface
        if counters is None:
            counters = psutil.net_io_counters(pernic=False)
            interface = "all"
        return interface, counters

    def _connection_states(self) -> tuple[dict[str, int], str]:
        try:
            connections = psutil.net_connections(kind="tcp")
            states = Counter(connection.status or "UNKNOWN" for connection in connections)
            return dict(states), "psutil"
        except (psutil.AccessDenied, PermissionError):
            completed = subprocess.run(
                ["ss", "-Htan"], capture_output=True, text=True, timeout=5, check=False
            )
            if completed.returncode != 0:
                return {}, "unavailable"
            states = Counter()
            for line in completed.stdout.splitlines():
                fields = line.split()
                if fields:
                    states[fields[0].upper()] += 1
            return dict(states), "ss"

    def _network_event(self):
        now = time.monotonic()
        interface, counters = self._network_counters()
        elapsed = 0.0
        rates = {"rx_bytes_per_second": 0.0, "tx_bytes_per_second": 0.0,
                 "rx_packets_per_second": 0.0, "tx_packets_per_second": 0.0}
        if self._previous_net is not None:
            previous_time, previous = self._previous_net
            elapsed = max(now - previous_time, 0.001)
            rates = {
                "rx_bytes_per_second": max(0.0, (counters.bytes_recv - previous.bytes_recv) / elapsed),
                "tx_bytes_per_second": max(0.0, (counters.bytes_sent - previous.bytes_sent) / elapsed),
                "rx_packets_per_second": max(0.0, (counters.packets_recv - previous.packets_recv) / elapsed),
                "tx_packets_per_second": max(0.0, (counters.packets_sent - previous.packets_sent) / elapsed),
            }
        self._previous_net = (now, counters)
        states, source = self._connection_states()
        total = sum(states.values())
        established = states.get("ESTABLISHED", 0)
        message = (
            f"connections={total} established={established} "
            f'rx={rates["rx_bytes_per_second"] / 1024:.1f}KB/s '
            f'tx={rates["tx_bytes_per_second"] / 1024:.1f}KB/s'
        )
        data = {
            "interface": interface,
            "rx_bytes": counters.bytes_recv,
            "tx_bytes": counters.bytes_sent,
            "rx_packets": counters.packets_recv,
            "tx_packets": counters.packets_sent,
            **{key: round(value, 2) for key, value in rates.items()},
            "sample_elapsed_seconds": round(elapsed, 3),
            "tcp_connections_total": total,
            "tcp_established": established,
            "tcp_time_wait": states.get("TIME_WAIT", 0),
            "tcp_listen": states.get("LISTEN", 0),
            "tcp_state_counts": states,
            "connection_collection_source": source,
        }
        return create_event(
            event_type="network_metrics",
            source="system",
            message=message,
            data=data,
        )

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.publish(self._system_event())
                self.publish(self._network_event())
            except (psutil.Error, OSError, subprocess.SubprocessError) as exc:
                self.logger.error("[SYSTEM] collection error: %s", exc)
            except Exception as exc:
                self.logger.exception("[SYSTEM] unexpected collector error: %s", exc)
            self.wait(self.poll_interval)
