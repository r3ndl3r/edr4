"""Normalized event contract shared by collectors, detection, and storage.

Event creation is also a privacy boundary: messages and structured data are
redacted before any consumer can display or persist them.
"""

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
    """Immutable identity and normalized payload for one observed event."""
    event_id: str
    timestamp: str
    host: str
    event_type: str
    source: str
    severity: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable representation of the complete event."""
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
    """Create a normalized event with UUID, host identity, and redaction.

    Args:
        event_type: Normalized event category consumed by storage and rules.
        source: Collector or subsystem that produced the event.
        severity: Logging-compatible severity label.
        message: Concise human-readable summary.
        data: Source-specific structured fields.
        timestamp: Optional source timestamp; current UTC time is used otherwise.

    Returns:
        A privacy-filtered ``TelemetryEvent`` ready for publication.
    """
    # Apply redaction here, before the object reaches the shared queue. Later
    # console and storage redaction are defense-in-depth rather than substitutes.
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
