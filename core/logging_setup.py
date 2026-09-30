"""Console logging configuration and event rendering."""

from __future__ import annotations

import json
import logging
from datetime import datetime

from core.events import TelemetryEvent
from core.redaction import redact_value

_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}
_LABELS = {
    "http_request": "HTTP",
    "journal_event": "JOURNAL",
    "process_snapshot": "PROCESS",
    "system_metrics": "SYSTEM",
    "network_metrics": "NETWORK",
    "service_status": "PROCESS",
    "detection": "DETECTION",
}


class _LocalTimeFormatter(logging.Formatter):
    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        return datetime.fromtimestamp(record.created).astimezone().strftime(datefmt or "%H:%M:%S")


def configure_logging(verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("edr4")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(_LocalTimeFormatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def should_display_event(event: TelemetryEvent, verbose: bool) -> bool:
    """Keep normal mode focused on findings and events needing attention."""
    if verbose:
        return True
    if event.event_type in {"detection", "service_status"}:
        return True
    return event.severity in {"warning", "error", "critical"}


def log_event(logger: logging.Logger, event: TelemetryEvent, verbose: bool) -> None:
    if not should_display_event(event, verbose):
        return
    label = _LABELS.get(event.event_type, event.source.upper())
    text = f"[{label}] {event.message}"
    if verbose:
        safe_data = redact_value(event.data)
        text += f" event_id={event.event_id} data={json.dumps(safe_data, sort_keys=True, ensure_ascii=False)}"
    logger.log(_LEVELS.get(event.severity, logging.INFO), text)
