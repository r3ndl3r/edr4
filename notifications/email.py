"""Gmail SMTP delivery for privacy-limited passive detection notifications."""

from __future__ import annotations

import smtplib
import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from email.message import EmailMessage
from email.utils import formataddr
from typing import Any

from core.redaction import redact_text, redact_value
from detection.base import Detection
from notifications.config import EmailAlertConfig

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_TIMEOUT_SECONDS = 15.0
SENDER_NAME = "EDR4 Security Alerts"

# Detection data is intentionally allowlisted. New detector fields do not enter
# email automatically merely because they were added to a telemetry event.
_EVIDENCE_FIELDS = (
    "source_ip",
    "path",
    "http_method",
    "response_status",
    "scope",
    "request_count",
    "response_count",
    "window_seconds",
    "threshold",
    "status_class",
    "error_count",
    "error_ratio",
    "threshold_ratio",
    "indicator_categories",
    "input_locations",
    "change",
    "service",
    "old_pid",
    "new_pid",
    "old_status",
    "new_status",
    "pid",
)


@dataclass(frozen=True, slots=True)
class EmailDeliveryResult:
    """Count immediate SMTP acceptances without retaining recipient addresses."""

    attempted: int
    accepted: int
    refused: int


def _single_line(value: object, maximum: int = 160) -> str:
    """Create a redacted bounded header-safe value."""
    text = redact_text(str(value), max_length=maximum)
    return " ".join(text.replace("\r", " ").replace("\n", " ").split())


def _display_value(value: Any) -> str:
    """Render one allowlisted evidence value without exposing arbitrary data."""
    safe_value = redact_value(value)
    if isinstance(safe_value, list):
        return ", ".join(_single_line(item) for item in safe_value)
    return _single_line(safe_value)


class GmailEmailNotifier:
    """Build and send plain-text alert messages through Gmail SMTP and TLS."""

    def __init__(
        self,
        config: EmailAlertConfig,
        *,
        host: str = SMTP_HOST,
        port: int = SMTP_PORT,
        timeout: float = SMTP_TIMEOUT_SECONDS,
        local_hostname: str | None = None,
    ) -> None:
        """Retain validated settings and non-secret transport parameters."""
        self.config = config
        self.host = host
        self.port = port
        self.timeout = timeout
        self.local_hostname = local_hostname or socket.gethostname()

    @property
    def recipient_count(self) -> int:
        """Return the destination count without exposing destination addresses."""
        return len(self.config.recipients)

    def build_message(self, detection: Detection) -> EmailMessage:
        """Construct a bounded message from allowlisted, redacted evidence."""
        severity = _single_line(detection.severity.upper(), maximum=16)
        detector = _single_line(detection.detector, maximum=80)
        subject = f"[EDR4][{severity}] {detector} on {_single_line(self.local_hostname, 80)}"

        lines = [
            "EDR4 generated a passive detection finding.",
            "",
            f"Timestamp: {datetime.now(UTC).isoformat()}",
            f"Host: {_single_line(self.local_hostname, 120)}",
            f"Severity: {severity.lower()}",
            f"Detector: {detector}",
            f"Source event ID: {_single_line(detection.event_id, 80)}",
            f"Summary: {_single_line(detection.message, 512)}",
        ]
        evidence = [
            (field, _display_value(detection.data[field]))
            for field in _EVIDENCE_FIELDS
            if field in detection.data
        ]
        if evidence:
            lines.extend(["", "Evidence:"])
            lines.extend(f"- {field}: {value}" for field, value in evidence)
        lines.extend(["", "This is a passive notification. EDR4 took no response action."])

        message = EmailMessage()
        message["From"] = formataddr((SENDER_NAME, self.config.username))
        message["To"] = ", ".join(self.config.recipients)
        message["Subject"] = subject
        message.set_content("\n".join(lines))
        return message

    def send(self, detection: Detection) -> EmailDeliveryResult:
        """Submit one message and report immediate per-recipient SMTP results."""
        message = self.build_message(detection)
        tls_context = ssl.create_default_context()
        with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as smtp:
            smtp.ehlo()
            smtp.starttls(context=tls_context)
            # RFC guidance and Python's smtplib documentation recommend EHLO
            # again after TLS because server capabilities may have changed.
            smtp.ehlo()
            smtp.login(self.config.username, self.config.app_password)
            refused = smtp.send_message(
                message,
                from_addr=self.config.username,
                to_addrs=list(self.config.recipients),
            )

        refused_count = len(refused or {})
        attempted = self.recipient_count
        return EmailDeliveryResult(
            attempted=attempted,
            accepted=max(0, attempted - refused_count),
            refused=refused_count,
        )
