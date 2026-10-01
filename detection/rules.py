"""Passive stateful rules for HTTP and Juice Shop process anomalies.

Rules consume only normalized event fields, retain bounded in-memory windows,
and emit evidence-oriented findings. They never alter traffic or host state.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime
from typing import Any

from core.events import TelemetryEvent
from detection.base import CooldownTracker, Detection


def _event_seconds(event: TelemetryEvent) -> float:
    """Use source event time for deterministic sliding windows."""
    try:
        return datetime.fromisoformat(event.timestamp.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return 0.0


def _number(value: Any, default: float = 0.0) -> float:
    """Convert an event value to float without allowing malformed input to escape."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class UrlSqlInjectionDetector:
    """Alert on sanitized SQL-injection indicators produced by the HTTP parser."""

    name = "url_sqli"
    _CATEGORIES = {
        "boolean_expression",
        "schema_enumeration",
        "sql_comment",
        "stacked_statement",
        "time_delay",
        "union_select",
    }
    _LOCATIONS = {"path", "query"}

    def __init__(self, *, cooldown_seconds: float) -> None:
        """Initialize per-source/path suppression for repeated SQLi findings."""
        self.cooldown = CooldownTracker(cooldown_seconds)

    def process(self, event: TelemetryEvent) -> list[Detection]:
        """Create a finding from sanitized URL SQLi metadata when present."""
        if event.event_type != "http_request" or event.data.get("sqli_suspected") is not True:
            return []
        categories = sorted({
            str(item) for item in event.data.get("sqli_indicator_categories", [])
            if str(item) in self._CATEGORIES
        })
        locations = sorted({
            str(item) for item in event.data.get("sqli_input_locations", [])
            if str(item) in self._LOCATIONS
        })
        if not categories or not locations:
            return []

        source = str(event.data.get("source_ip") or "unknown")
        path = str(event.data.get("path") or "/")
        now = _event_seconds(event)
        cooldown_key = f"{source}:{path}:{','.join(categories)}"
        if not self.cooldown.allow(cooldown_key, now):
            return []
        return [Detection(
            detector=self.name,
            severity="warning",
            message=(
                "Possible URL-based SQL injection indicators observed: "
                f"categories={','.join(categories)} path={path} src={source}"
            ),
            event_id=event.event_id,
            data={
                "source_ip": source,
                "path": path,
                "http_method": event.data.get("http_method"),
                "response_status": event.data.get("response_status"),
                "indicator_categories": categories,
                "input_locations": locations,
            },
        )]


class RequestRateDetector:
    """Detect global and per-source HTTP request bursts."""

    name = "request_rate"

    def __init__(self, *, window_seconds: float, threshold: int, per_source_threshold: int,
                 cooldown_seconds: float) -> None:
        """Configure global and per-source sliding-window thresholds."""
        self.window_seconds = max(1.0, window_seconds)
        self.threshold = max(1, threshold)
        self.per_source_threshold = max(1, per_source_threshold)
        self.events: deque[tuple[float, str]] = deque()
        self.cooldown = CooldownTracker(cooldown_seconds)

    def process(self, event: TelemetryEvent) -> list[Detection]:
        """Track one HTTP event and emit newly eligible rate findings."""
        if event.event_type != "http_request":
            return []
        now = _event_seconds(event)
        source = str(event.data.get("source_ip") or "unknown")
        # The deque is a sliding time window: append the newest request on the
        # right, then remove expired requests from the left.
        self.events.append((now, source))
        cutoff = now - self.window_seconds
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

        findings: list[Detection] = []
        total = len(self.events)
        # Global and per-source limits serve different purposes. The global
        # limit can see distributed traffic; the source limit sees one client.
        if total >= self.threshold and self.cooldown.allow("global", now):
            findings.append(Detection(
                detector=self.name,
                severity="warning",
                message=f"HTTP request-rate threshold exceeded: {total} requests/{self.window_seconds:g}s",
                event_id=event.event_id,
                data={"scope": "global", "request_count": total, "window_seconds": self.window_seconds,
                      "threshold": self.threshold},
            ))

        source_count = sum(1 for _, observed_source in self.events if observed_source == source)
        if source_count >= self.per_source_threshold and self.cooldown.allow(f"source:{source}", now):
            findings.append(Detection(
                detector=self.name,
                severity="warning",
                message=(f"Per-source HTTP request-rate threshold exceeded: "
                         f"{source_count} requests/{self.window_seconds:g}s src={source}"),
                event_id=event.event_id,
                data={"scope": "source", "source_ip": source, "request_count": source_count,
                      "window_seconds": self.window_seconds, "threshold": self.per_source_threshold},
            ))
        return findings


class RepeatedAuth401Detector:
    """Detect repeated 401 responses on authentication-like paths."""

    name = "repeated_auth_401"

    def __init__(self, *, window_seconds: float, threshold: int, path_fragments: list[str],
                 cooldown_seconds: float) -> None:
        """Configure authentication paths, failure threshold, and time window."""
        self.window_seconds = max(1.0, window_seconds)
        self.threshold = max(1, threshold)
        self.path_fragments = [fragment.lower() for fragment in path_fragments if fragment]
        self.events: dict[str, deque[float]] = defaultdict(deque)
        self.cooldown = CooldownTracker(cooldown_seconds)

    def process(self, event: TelemetryEvent) -> list[Detection]:
        """Track authentication-like 401 responses per source address."""
        if event.event_type != "http_request":
            return []
        status = int(_number(event.data.get("response_status"), -1))
        path = str(event.data.get("path") or "").lower()
        if status != 401 or not any(fragment in path for fragment in self.path_fragments):
            return []

        now = _event_seconds(event)
        source = str(event.data.get("source_ip") or "unknown")
        # defaultdict automatically creates an empty deque when an address is
        # first observed, avoiding a separate existence check on every event.
        observations = self.events[source]
        observations.append(now)
        cutoff = now - self.window_seconds
        while observations and observations[0] < cutoff:
            observations.popleft()
        count = len(observations)
        if count < self.threshold or not self.cooldown.allow(source, now):
            return []
        return [Detection(
            detector=self.name,
            severity="warning",
            message=(f"Repeated authentication-like 401 responses: "
                     f"{count}/{self.window_seconds:g}s src={source}"),
            event_id=event.event_id,
            data={"source_ip": source, "response_status": 401, "response_count": count,
                  "window_seconds": self.window_seconds, "threshold": self.threshold,
                  "path": str(event.data.get("path") or "")},
        )]


class StatusAnomalyDetector:
    """Detect elevated HTTP client- or server-error ratios."""

    name = "status_anomaly"

    def __init__(self, *, window_seconds: float, minimum_requests: int, client_error_ratio: float,
                 server_error_ratio: float, cooldown_seconds: float) -> None:
        """Configure minimum volume and HTTP error-ratio thresholds."""
        self.window_seconds = max(1.0, window_seconds)
        self.minimum_requests = max(1, minimum_requests)
        self.client_error_ratio = min(max(client_error_ratio, 0.0), 1.0)
        self.server_error_ratio = min(max(server_error_ratio, 0.0), 1.0)
        self.events: deque[tuple[float, int]] = deque()
        self.cooldown = CooldownTracker(cooldown_seconds)

    def process(self, event: TelemetryEvent) -> list[Detection]:
        """Evaluate rolling HTTP status ratios after minimum volume is reached."""
        if event.event_type != "http_request":
            return []
        status = int(_number(event.data.get("response_status"), -1))
        if not 100 <= status <= 599:
            return []
        now = _event_seconds(event)
        self.events.append((now, status))
        cutoff = now - self.window_seconds
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()
        total = len(self.events)
        # Ratios calculated from only a few requests are unstable and noisy.
        # Wait for a meaningful sample before assessing the error percentage.
        if total < self.minimum_requests:
            return []

        client_errors = sum(1 for _, observed in self.events if 400 <= observed <= 499)
        server_errors = sum(1 for _, observed in self.events if 500 <= observed <= 599)
        client_ratio = client_errors / total
        server_ratio = server_errors / total
        findings: list[Detection] = []
        if server_errors > 0 and server_ratio >= self.server_error_ratio and self.cooldown.allow("5xx", now):
            findings.append(Detection(
                detector=self.name,
                severity="error",
                message=f"HTTP 5xx ratio elevated: {server_errors}/{total} ({server_ratio:.0%})",
                event_id=event.event_id,
                data={"status_class": "5xx", "error_count": server_errors, "request_count": total,
                      "error_ratio": round(server_ratio, 4), "threshold_ratio": self.server_error_ratio,
                      "window_seconds": self.window_seconds},
            ))
        if client_errors > 0 and client_ratio >= self.client_error_ratio and self.cooldown.allow("4xx", now):
            findings.append(Detection(
                detector=self.name,
                severity="warning",
                message=f"HTTP 4xx ratio elevated: {client_errors}/{total} ({client_ratio:.0%})",
                event_id=event.event_id,
                data={"status_class": "4xx", "error_count": client_errors, "request_count": total,
                      "error_ratio": round(client_ratio, 4), "threshold_ratio": self.client_error_ratio,
                      "window_seconds": self.window_seconds},
            ))
        return findings


class ProcessStateDetector:
    """Detect service loss, PID replacement, and abnormal process states."""

    name = "process_state_change"

    def __init__(self, *, abnormal_states: list[str], cooldown_seconds: float) -> None:
        """Configure abnormal states and initialize prior service identity."""
        self.abnormal_states = {state.lower() for state in abnormal_states}
        self.last_pid: int | None = None
        self.last_status: str | None = None
        self.available = True
        self.cooldown = CooldownTracker(cooldown_seconds)

    def process(self, event: TelemetryEvent) -> list[Detection]:
        """Detect service loss, PID replacement, and abnormal state transitions."""
        now = _event_seconds(event)
        if event.event_type == "service_status":
            if event.data.get("available") is False:
                self.available = False
                if self.cooldown.allow("unavailable", now):
                    return [Detection(
                        detector=self.name, severity="error",
                        message="Juice Shop service has no active MainPID", event_id=event.event_id,
                        data={"change": "service_unavailable", "service": event.data.get("service")},
                    )]
            new_pid = event.data.get("new_pid")
            old_pid = event.data.get("old_pid")
            if new_pid is not None and old_pid is not None:
                self.last_pid = int(new_pid)
                self.available = True
                if self.cooldown.allow("pid_change", now):
                    return [Detection(
                        detector=self.name, severity="warning",
                        message=f"Juice Shop process PID changed: {old_pid} -> {new_pid}",
                        event_id=event.event_id,
                        data={"change": "pid", "old_pid": int(old_pid), "new_pid": int(new_pid)},
                    )]
            return []

        if event.event_type != "process_snapshot":
            return []
        pid = int(_number(event.data.get("pid"), 0))
        status = str(event.data.get("status") or "unknown").lower()
        findings: list[Detection] = []
        # The first snapshot establishes a baseline. Later snapshots are
        # compared with last_pid and last_status to identify real transitions.
        if self.last_pid is not None and pid and pid != self.last_pid and self.cooldown.allow("pid_change", now):
            findings.append(Detection(
                detector=self.name, severity="warning",
                message=f"Juice Shop process PID changed: {self.last_pid} -> {pid}",
                event_id=event.event_id,
                data={"change": "pid", "old_pid": self.last_pid, "new_pid": pid},
            ))
        if status in self.abnormal_states and status != self.last_status and self.cooldown.allow(f"status:{status}", now):
            findings.append(Detection(
                detector=self.name, severity="error",
                message=f"Juice Shop process entered abnormal state: {status}",
                event_id=event.event_id,
                data={"change": "status", "old_status": self.last_status, "new_status": status, "pid": pid},
            ))
        # Always retain the latest valid state, even when it does not produce a
        # finding, so the following comparison uses current reality.
        self.last_pid = pid or self.last_pid
        self.last_status = status
        self.available = True
        return findings
