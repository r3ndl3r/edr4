"""Dynamic process telemetry for the systemd-managed Juice Shop service.

The MainPID is resolved on every polling cycle so service restarts do not
require an EDR restart. Missing or replaced processes become explicit events.
"""

from __future__ import annotations

import logging
import subprocess
import threading
from datetime import UTC, datetime

import psutil

from collectors.base import BaseCollector
from core.event_bus import EventBus
from core.events import create_event


class ProcessCollector(BaseCollector):
    """Track the current Juice Shop process and publish bounded snapshots."""

    def __init__(
        self,
        event_bus: EventBus,
        stop_event: threading.Event,
        logger: logging.Logger,
        service: str,
        poll_interval: float,
    ) -> None:
        """Configure service discovery and the process polling cadence."""
        super().__init__("process", event_bus, stop_event, logger)
        self.service = service
        self.poll_interval = poll_interval
        self._process: psutil.Process | None = None
        self._last_missing = False

    def _main_pid(self) -> int:
        """Resolve the service MainPID, returning zero when unavailable."""
        completed = subprocess.run(
            ["systemctl", "show", self.service, "-p", "MainPID", "--value"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if completed.returncode != 0:
            return 0
        try:
            return int(completed.stdout.strip())
        except ValueError:
            return 0

    def _attach(self, pid: int) -> None:
        """Attach psutil to a new PID and prime CPU percentage sampling."""
        self._process = psutil.Process(pid)
        # psutil calculates CPU percentage from two readings. The first call
        # establishes the baseline and is intentionally discarded.
        self._process.cpu_percent(interval=None)
        self.logger.info("[PROCESS] attached to %s pid=%d", self.service, pid)

    def _emit_missing(self) -> None:
        """Publish one service-unavailable transition and reset process state."""
        if not self._last_missing:
            self.publish(create_event(
                event_type="service_status",
                source="process",
                severity="warning",
                message=f"{self.service} has no active MainPID; retrying",
                data={"service": self.service, "available": False},
            ))
        self._last_missing = True
        self._process = None

    def _snapshot(self, process: psutil.Process) -> None:
        """Collect and publish one bounded Juice Shop process snapshot."""
        with process.oneshot():
            memory = process.memory_info()
            children = process.children(recursive=False)
            cpu = process.cpu_percent(interval=None)
            memory_percent = process.memory_percent()
            data = {
                "pid": process.pid,
                "ppid": process.ppid(),
                "process_name": process.name(),
                "username": process.username(),
                "status": process.status(),
                "create_time": datetime.fromtimestamp(process.create_time(), UTC).isoformat(),
                "cpu_percent": round(cpu, 2),
                "memory_percent": round(memory_percent, 2),
                "rss_bytes": memory.rss,
                "thread_count": process.num_threads(),
                "child_process_count": len(children),
            }
        message = (
            f'{data["process_name"]} pid={data["pid"]} cpu={data["cpu_percent"]:.1f}% '
            f'mem={data["rss_bytes"] / (1024 * 1024):.1f}MB children={data["child_process_count"]}'
        )
        self.publish(create_event(
            event_type="process_snapshot",
            source="process",
            message=message,
            data=data,
        ))

    def run(self) -> None:
        """Poll service identity and metrics until cooperative shutdown."""
        while not self.stop_event.is_set():
            try:
                pid = self._main_pid()
                if pid <= 0:
                    self._emit_missing()
                else:
                    if self._process is None or self._process.pid != pid or not self._process.is_running():
                        old_pid = self._process.pid if self._process is not None else None
                        self._attach(pid)
                        # A changed MainPID normally indicates a service restart;
                        # emit the transition rather than requiring an EDR restart.
                        if old_pid is not None and old_pid != pid:
                            self.publish(create_event(
                                event_type="service_status",
                                source="process",
                                severity="warning",
                                message=f"{self.service} PID changed {old_pid} -> {pid}",
                                data={"service": self.service, "old_pid": old_pid, "new_pid": pid},
                            ))
                    self._last_missing = False
                    self._snapshot(self._process)
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                self._process = None
            except (psutil.AccessDenied, subprocess.SubprocessError, OSError) as exc:
                self.logger.error("[PROCESS] collection error: %s", exc)
            except Exception as exc:
                self.logger.exception("[PROCESS] unexpected collector error: %s", exc)
            self.wait(self.poll_interval)
