"""Unit tests for passive detectors and normalized finding persistence."""

from __future__ import annotations

import unittest
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from core.events import TelemetryEvent, create_event
from detection.base import detection_to_event
from detection.engine import DetectionEngine
from detection.rules import (
    ProcessStateDetector,
    RepeatedAuth401Detector,
    RequestRateDetector,
    StatusAnomalyDetector,
    UrlSqlInjectionDetector,
)
from storage.database import EventDatabase


BASE_TIME = datetime(2026, 9, 30, 10, 0, tzinfo=UTC)


def http_event(offset: float, *, status: int = 200, source: str = "192.0.2.10",
               path: str = "/rest/products") -> TelemetryEvent:
    """Build a synthetic HTTP event at a controlled offset from BASE_TIME."""
    return create_event(
        timestamp=(BASE_TIME + timedelta(seconds=offset)).isoformat(),
        event_type="http_request",
        source="morgan",
        message=f"GET {path} -> {status}",
        data={"source_ip": source, "path": path, "response_status": status},
    )


def process_event(offset: float, *, pid: int, status: str) -> TelemetryEvent:
    """Build a synthetic process snapshot for state-transition tests."""
    return create_event(
        timestamp=(BASE_TIME + timedelta(seconds=offset)).isoformat(),
        event_type="process_snapshot",
        source="process",
        message="process snapshot",
        data={"pid": pid, "status": status},
    )


class RequestRateDetectorTests(unittest.TestCase):
    """Verify request-rate windows, thresholds, and cooldown behavior."""

    def test_global_and_source_rate_thresholds_and_cooldown(self) -> None:
        detector = RequestRateDetector(
            window_seconds=10, threshold=3, per_source_threshold=3, cooldown_seconds=60
        )
        self.assertEqual(detector.process(http_event(0)), [])
        self.assertEqual(detector.process(http_event(1)), [])
        findings = detector.process(http_event(2))
        self.assertEqual({item.data["scope"] for item in findings}, {"global", "source"})
        self.assertEqual(detector.process(http_event(3)), [])

    def test_old_requests_leave_window(self) -> None:
        detector = RequestRateDetector(
            window_seconds=5, threshold=3, per_source_threshold=99, cooldown_seconds=0
        )
        detector.process(http_event(0))
        detector.process(http_event(1))
        self.assertEqual(detector.process(http_event(10)), [])


class UrlSqlInjectionDetectorTests(unittest.TestCase):
    """Verify sanitized URL evidence can produce SQLi findings."""

    def test_sanitized_url_indicators_generate_finding(self) -> None:
        detector = UrlSqlInjectionDetector(cooldown_seconds=60)
        event = create_event(
            timestamp=BASE_TIME.isoformat(),
            event_type="http_request",
            source="morgan",
            message="GET /rest/products/search -> 200",
            data={
                "source_ip": "192.0.2.10",
                "path": "/rest/products/search",
                "http_method": "GET",
                "response_status": 200,
                "sqli_suspected": True,
                "sqli_indicator_categories": ["boolean_expression", "sql_comment"],
                "sqli_input_locations": ["query"],
            },
        )
        findings = detector.process(event)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector, "url_sqli")
        self.assertEqual(findings[0].data["input_locations"], ["query"])
        self.assertEqual(detector.process(event), [])

    def test_unflagged_request_is_ignored(self) -> None:
        detector = UrlSqlInjectionDetector(cooldown_seconds=0)
        self.assertEqual(detector.process(http_event(0)), [])


class Auth401DetectorTests(unittest.TestCase):
    """Verify authentication-like 401 responses are counted selectively."""

    def test_repeated_authentication_like_401s(self) -> None:
        detector = RepeatedAuth401Detector(
            window_seconds=60, threshold=3, path_fragments=["/login"], cooldown_seconds=60
        )
        self.assertEqual(detector.process(http_event(0, status=401, path="/rest/user/login")), [])
        self.assertEqual(detector.process(http_event(1, status=200, path="/rest/user/login")), [])
        self.assertEqual(detector.process(http_event(2, status=401, path="/rest/user/login")), [])
        findings = detector.process(http_event(3, status=401, path="/rest/user/login"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector, "repeated_auth_401")
        self.assertNotIn("brute force", findings[0].message.lower())

    def test_non_auth_401_is_ignored(self) -> None:
        detector = RepeatedAuth401Detector(
            window_seconds=60, threshold=1, path_fragments=["/login"], cooldown_seconds=0
        )
        self.assertEqual(detector.process(http_event(0, status=401, path="/api/private")), [])


class StatusAnomalyDetectorTests(unittest.TestCase):
    """Verify rolling HTTP client- and server-error ratio findings."""

    def test_client_error_ratio(self) -> None:
        detector = StatusAnomalyDetector(
            window_seconds=60, minimum_requests=4, client_error_ratio=0.5,
            server_error_ratio=1.0, cooldown_seconds=60,
        )
        statuses = [200, 404, 401, 200]
        findings = []
        for offset, status in enumerate(statuses):
            findings.extend(detector.process(http_event(offset, status=status)))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].data["status_class"], "4xx")
        self.assertEqual(findings[0].data["error_ratio"], 0.5)

    def test_server_error_ratio(self) -> None:
        detector = StatusAnomalyDetector(
            window_seconds=60, minimum_requests=4, client_error_ratio=1.0,
            server_error_ratio=0.25, cooldown_seconds=60,
        )
        findings = []
        for offset, status in enumerate([200, 200, 503, 200]):
            findings.extend(detector.process(http_event(offset, status=status)))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "error")
        self.assertEqual(findings[0].data["status_class"], "5xx")


class ProcessStateDetectorTests(unittest.TestCase):
    """Verify service loss, PID changes, and abnormal process states."""

    def test_pid_and_abnormal_state_changes(self) -> None:
        detector = ProcessStateDetector(
            abnormal_states=["zombie", "stopped", "dead"], cooldown_seconds=0
        )
        self.assertEqual(detector.process(process_event(0, pid=100, status="sleeping")), [])
        self.assertEqual(detector.process(process_event(1, pid=100, status="running")), [])
        state_findings = detector.process(process_event(2, pid=100, status="zombie"))
        self.assertEqual(len(state_findings), 1)
        self.assertEqual(state_findings[0].data["change"], "status")
        pid_findings = detector.process(process_event(3, pid=200, status="sleeping"))
        self.assertEqual(len(pid_findings), 1)
        self.assertEqual(pid_findings[0].data["change"], "pid")

    def test_service_unavailable_event(self) -> None:
        detector = ProcessStateDetector(abnormal_states=["zombie"], cooldown_seconds=60)
        event = create_event(
            timestamp=BASE_TIME.isoformat(), event_type="service_status", source="process",
            severity="warning", message="missing",
            data={"service": "juice-shop.service", "available": False},
        )
        findings = detector.process(event)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].data["change"], "service_unavailable")
        self.assertEqual(detector.process(event), [])


class DetectionEngineTests(unittest.TestCase):
    """Verify engine configuration and conversion to stored telemetry events."""

    def test_disabled_engine_returns_no_findings(self) -> None:
        engine = DetectionEngine({"enabled": False})
        self.assertEqual(engine.process(http_event(0, status=500)), [])

    def test_finding_is_normalised_and_persisted(self) -> None:
        detector = RequestRateDetector(
            window_seconds=10, threshold=1, per_source_threshold=99, cooldown_seconds=60
        )
        source_event = http_event(0)
        finding = detector.process(source_event)[0]
        event = detection_to_event(finding)
        self.assertEqual(event.event_type, "detection")
        self.assertEqual(event.data["detector"], "request_rate")
        self.assertEqual(event.data["source_event_id"], source_event.event_id)
        with tempfile.TemporaryDirectory() as directory:
            database = EventDatabase(Path(directory) / "events.db")
            self.assertTrue(database.insert_event(event))
            stored_type = database.connection.execute(
                "SELECT event_type FROM events WHERE event_id = ?", (event.event_id,)
            ).fetchone()[0]
            database.close()
        self.assertEqual(stored_type, "detection")


if __name__ == "__main__":
    unittest.main()
