"""Normalised telemetry event model."""

from __future__ import annotations

import socket
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from core.redaction import redact_text, redact_value


def utc_now_iso() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True, slots=True)
class TelemetryEvent:
    event_id: str
    timestamp: str
    host: str
    event_type: str
    source: str
    severity: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def create_event(
    *,
    event_type: str,
    source: str,
    severity: str = "info",
    message: str,
    data: dict[str, Any] | None = None,
    timestamp: str | None = None,
) -> TelemetryEvent:
    """Create a normalised event with redaction applied at the boundary."""
    return TelemetryEvent(
        event_id=str(uuid.uuid4()),
        timestamp=timestamp or utc_now_iso(),
        host=socket.gethostname(),
        event_type=event_type,
        source=source,
        severity=severity,
        message=redact_text(message, max_length=512),
        data=redact_value(data or {}),
    )
