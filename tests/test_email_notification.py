"""Unit tests for privacy-limited Gmail SMTP alert delivery."""

from __future__ import annotations

import logging
import threading
import unittest
from unittest.mock import patch

from detection.base import Detection
from notifications.config import EmailAlertConfig
from notifications.email import EmailDeliveryResult, GmailEmailNotifier
from notifications.manager import NotificationManager


def example_detection(severity: str = "warning") -> Detection:
    """Build a synthetic finding containing allowed and forbidden evidence."""
    return Detection(
        detector="request_rate",
        severity=severity,
        message="Synthetic request-rate threshold exceeded",
        event_id="00000000-0000-0000-0000-000000000001",
        data={
            "source_ip": "192.0.2.10",
            "request_count": 35,
            "window_seconds": 10,
            "password": "must-not-enter-email",
            "arbitrary_field": "must-not-enter-email-either",
        },
    )


class GmailEmailNotifierTests(unittest.TestCase):
    """Verify message minimization and secure SMTP operation order."""

    def setUp(self) -> None:
        """Create a notifier containing synthetic, non-production values."""
        self.config = EmailAlertConfig(
            username="sender@example.com",
            app_password="synthetic-app-password",
            recipients=("first@example.com", "second@example.com"),
        )
        self.notifier = GmailEmailNotifier(
            self.config,
            host="smtp.example.com",
            port=587,
            timeout=5,
            local_hostname="edr-test-host",
        )

    def test_message_contains_allowlisted_evidence_only(self) -> None:
        message = self.notifier.build_message(example_detection())
        rendered = message.as_string()
        self.assertIn("request_rate", rendered)
        self.assertIn("192.0.2.10", rendered)
        self.assertIn("request_count: 35", rendered)
        self.assertNotIn("must-not-enter-email", rendered)
        self.assertNotIn("must-not-enter-email-either", rendered)
        self.assertNotIn("synthetic-app-password", rendered)

    @patch("notifications.email.smtplib.SMTP")
    def test_send_uses_starttls_before_login(self, smtp_class) -> None:
        smtp = smtp_class.return_value.__enter__.return_value
        smtp.send_message.return_value = {}
        result = self.notifier.send(example_detection())

        smtp_class.assert_called_once_with("smtp.example.com", 587, timeout=5)
        smtp.starttls.assert_called_once()
        smtp.login.assert_called_once_with("sender@example.com", "synthetic-app-password")
        smtp.send_message.assert_called_once()
        call_names = [call[0] for call in smtp.mock_calls]
        self.assertLess(call_names.index("starttls"), call_names.index("login"))
        self.assertLess(call_names.index("login"), call_names.index("send_message"))
        self.assertEqual(
            result,
            EmailDeliveryResult(attempted=2, accepted=2, refused=0),
        )

    @patch("notifications.email.smtplib.SMTP")
    def test_send_counts_partial_refusal_without_addresses(self, smtp_class) -> None:
        smtp = smtp_class.return_value.__enter__.return_value
        smtp.send_message.return_value = {"second@example.com": (550, b"rejected")}

        result = self.notifier.send(example_detection())

        self.assertEqual(
            result,
            EmailDeliveryResult(attempted=2, accepted=1, refused=1),
        )
        self.assertNotIn("example.com", repr(result))


class _RecordingNotifier:
    """Thread-safe test double for notification manager behavior."""

    recipient_count = 1
    timeout = 0.1

    def __init__(self, failures: int = 0) -> None:
        """Configure how many synthetic attempts fail before success."""
        self.failures = failures
        self.attempts = 0
        self.sent = threading.Event()

    def send(self, _detection: Detection) -> EmailDeliveryResult:
        """Record attempts and optionally fail before reporting delivery."""
        self.attempts += 1
        if self.attempts <= self.failures:
            raise OSError("synthetic-sensitive-server-response")
        self.sent.set()
        return EmailDeliveryResult(attempted=1, accepted=1, refused=0)


class NotificationManagerTests(unittest.TestCase):
    """Verify filtering, background delivery, retries, and safe errors."""

    def setUp(self) -> None:
        """Use a non-propagating logger so tests do not pollute console output."""
        self.logger = logging.getLogger(f"edr4-test-email-{id(self)}")
        self.logger.propagate = False
        self.logger.handlers = [logging.NullHandler()]

    def test_info_findings_are_not_queued(self) -> None:
        notifier = _RecordingNotifier()
        manager = NotificationManager(notifier, self.logger)
        self.assertFalse(manager.submit(example_detection("info")))
        self.assertEqual(notifier.attempts, 0)

    def test_warning_is_delivered_by_background_worker(self) -> None:
        notifier = _RecordingNotifier()
        manager = NotificationManager(notifier, self.logger, retry_delay_seconds=0)
        manager.start()
        try:
            self.assertTrue(manager.submit(example_detection()))
            self.assertTrue(notifier.sent.wait(timeout=1))
        finally:
            manager.stop()
        self.assertEqual(notifier.attempts, 1)

    def test_delivery_retries_once(self) -> None:
        notifier = _RecordingNotifier(failures=1)
        manager = NotificationManager(notifier, self.logger, retry_delay_seconds=0)
        manager._deliver(example_detection())
        self.assertEqual(notifier.attempts, 2)
        self.assertTrue(notifier.sent.is_set())

    def test_failure_log_does_not_include_exception_text(self) -> None:
        notifier = _RecordingNotifier(failures=2)
        manager = NotificationManager(notifier, logging.getLogger("edr4-test-email-errors"),
                                      retry_delay_seconds=0)
        with self.assertLogs("edr4-test-email-errors", level="ERROR") as captured:
            manager._deliver(example_detection())
        output = "\n".join(captured.output)
        self.assertIn("OSError", output)
        self.assertNotIn("synthetic-sensitive-server-response", output)

    def test_partial_refusal_logs_counts_without_addresses(self) -> None:
        manager = NotificationManager(
            None,
            logging.getLogger("edr4-test-email-partial"),
        )
        result = EmailDeliveryResult(attempted=2, accepted=1, refused=1)
        with self.assertLogs("edr4-test-email-partial", level="WARNING") as captured:
            manager._report_result(example_detection(), result)
        output = "\n".join(captured.output)
        self.assertIn("accepted=1 refused=1", output)
        self.assertNotIn("example.com", output)


if __name__ == "__main__":
    unittest.main()
