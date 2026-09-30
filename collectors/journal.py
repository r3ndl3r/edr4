"""Juice Shop systemd journal follower."""

from __future__ import annotations

import json
import logging
import subprocess
import threading
from datetime import UTC, datetime

from collectors.base import BaseCollector
from core.event_bus import EventBus
from core.events import create_event

_PRIORITY = {
    0: "critical",
    1: "critical",
    2: "critical",
    3: "error",
    4: "warning",
    5: "info",
    6: "info",
    7: "debug",
}


class JournalCollector(BaseCollector):
    def __init__(
        self,
        event_bus: EventBus,
        stop_event: threading.Event,
        logger: logging.Logger,
        service: str,
        retry_seconds: float = 5.0,
    ) -> None:
        super().__init__("journal", event_bus, stop_event, logger)
        self.service = service
        self.retry_seconds = retry_seconds
        self._process: subprocess.Popen[str] | None = None

    def _parse(self, line: str):
        try:
            record = json.loads(line)
            micros = int(record.get("__REALTIME_TIMESTAMP", "0"))
            timestamp = datetime.fromtimestamp(micros / 1_000_000, UTC).isoformat() if micros else None
            priority = int(record.get("PRIORITY", 6))
            message = str(record.get("MESSAGE", ""))
            if not message:
                return None
            return create_event(
                timestamp=timestamp,
                event_type="journal_event",
                source="journal",
                severity=_PRIORITY.get(priority, "info"),
                message=message,
                data={
                    "priority": priority,
                    "systemd_unit": record.get("_SYSTEMD_UNIT", self.service),
                    "pid": _safe_int(record.get("_PID")),
                    "identifier": record.get("SYSLOG_IDENTIFIER"),
                },
            )
        except (ValueError, TypeError, json.JSONDecodeError):
            return None

    def run(self) -> None:
        command = ["journalctl", "-u", self.service, "-f", "-n", "0", "-o", "json", "--no-pager"]
        while not self.stop_event.is_set():
            try:
                self._process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
                assert self._process.stdout is not None
                for line in self._process.stdout:
                    if self.stop_event.is_set():
                        break
                    event = self._parse(line)
                    if event is not None:
                        self.publish(event)
                    else:
                        self.logger.debug("[JOURNAL] skipped malformed journal record")
                return_code = self._process.poll()
                if not self.stop_event.is_set():
                    error = self._process.stderr.read().strip() if self._process.stderr else ""
                    self.logger.error("[JOURNAL] journalctl exited rc=%s %s", return_code, error[:300])
            except Exception as exc:
                if not self.stop_event.is_set():
                    self.logger.error("[JOURNAL] collector error: %s", exc)
            finally:
                self._terminate_process()
            self.wait(self.retry_seconds)

    def _terminate_process(self) -> None:
        process = self._process
        self._process = None
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)

    def stop(self) -> None:
        self.stop_event.set()
        self._terminate_process()


def _safe_int(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None
