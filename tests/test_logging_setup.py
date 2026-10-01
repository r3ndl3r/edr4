"""Unit tests for concise and verbose console visibility decisions."""

from __future__ import annotations

import unittest

from core.events import create_event
from core.logging_setup import should_display_event


class ConsoleVisibilityTests(unittest.TestCase):
    """Verify normal mode stays quiet while retaining important messages."""

    def test_normal_mode_hides_routine_telemetry(self) -> None:
        for event_type in ("http_request", "journal_event", "process_snapshot",
                           "system_metrics", "network_metrics"):
            event = create_event(
                event_type=event_type,
                source="test",
                severity="info",
                message="routine event",
                data={},
            )
            self.assertFalse(should_display_event(event, verbose=False))

    def test_normal_mode_shows_events_needing_attention(self) -> None:
        warning = create_event(
            event_type="http_request",
            source="morgan",
            severity="warning",
            message="POST /rest/user/login -> 401",
            data={},
        )
        detection = create_event(
            event_type="detection",
            source="detection",
            severity="info",
            message="finding",
            data={},
        )
        service_change = create_event(
            event_type="service_status",
            source="process",
            severity="info",
            message="service state changed",
            data={},
        )
        self.assertTrue(should_display_event(warning, verbose=False))
        self.assertTrue(should_display_event(detection, verbose=False))
        self.assertTrue(should_display_event(service_change, verbose=False))

    def test_verbose_mode_shows_routine_events(self) -> None:
        event = create_event(
            event_type="system_metrics",
            source="system",
            severity="info",
            message="routine event",
            data={},
        )
        self.assertTrue(should_display_event(event, verbose=True))


if __name__ == "__main__":
    unittest.main()
