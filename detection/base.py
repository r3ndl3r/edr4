"""Detection interface definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from core.events import TelemetryEvent, create_event


@dataclass(frozen=True, slots=True)
class Detection:
    detector: str
    severity: str
    message: str
    event_id: str
    data: dict[str, Any] = field(default_factory=dict)


class Detector(Protocol):
    def process(self, event: TelemetryEvent) -> list[Detection]: ...


class CooldownTracker:
    """Suppress repeated findings for the same rule/scope."""

    def __init__(self, cooldown_seconds: float) -> None:
        self.cooldown_seconds = max(0.0, cooldown_seconds)
        self._last_alert: dict[str, float] = {}

    def allow(self, key: str, current_time: float) -> bool:
        previous = self._last_alert.get(key)
        if previous is not None and current_time - previous < self.cooldown_seconds:
            return False
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
