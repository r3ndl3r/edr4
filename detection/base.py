"""Common passive-detection contracts and cooldown state.

Detection findings contain evidence metadata only. Conversion into the common
event model occurs before console display or persistence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from core.events import TelemetryEvent, create_event


@dataclass(frozen=True, slots=True)
class Detection:
    """One passive finding derived from a source telemetry event."""
    detector: str
    severity: str
    message: str
    event_id: str
    data: dict[str, Any] = field(default_factory=dict)


class Detector(Protocol):
    """Structural interface implemented by every passive detection rule."""

    def process(self, event: TelemetryEvent) -> list[Detection]:
        """Evaluate one event and return zero or more findings."""
        ...


class CooldownTracker:
    """Suppress repeated findings for the same rule/scope."""

    def __init__(self, cooldown_seconds: float) -> None:
        """Create per-key alert state with a non-negative cooldown."""
        self.cooldown_seconds = max(0.0, cooldown_seconds)
        self._last_alert: dict[str, float] = {}

    def allow(self, key: str, current_time: float) -> bool:
        """Return true once per key within the configured cooldown period."""
        # Keys create independent cooldown scopes. Suppressing repeated alerts
        # for one source address does not hide an alert from another source.
        previous = self._last_alert.get(key)
        if previous is not None and current_time - previous < self.cooldown_seconds:
            return False
        # Only an alert that is actually allowed updates the timer. Suppressed
        # events cannot keep extending the cooldown forever.
        self._last_alert[key] = current_time
        return True


def detection_to_event(detection: Detection) -> TelemetryEvent:
    """Convert a passive finding into the common event model."""
    return create_event(
        event_type="detection",
        source="detection",
        severity=detection.severity,
        message=detection.message,
        data={
            "detector": detection.detector,
            "source_event_id": detection.event_id,
            **detection.data,
        },
    )
