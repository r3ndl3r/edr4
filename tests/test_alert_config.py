"""Unit tests for strict, local-only Gmail alert configuration loading."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from notifications.config import AlertConfigError, load_email_alert_config


class AlertConfigTests(unittest.TestCase):
    """Verify parsing, required values, permissions, and secret-safe objects."""

    def setUp(self) -> None:
        """Create an isolated directory for permission-sensitive files."""
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "alerts.cfg"

    def tearDown(self) -> None:
        """Remove temporary configuration files after each test."""
        self.temporary.cleanup()

    def write_config(self, content: str, mode: int = 0o600) -> None:
        """Write synthetic configuration and apply explicit test permissions."""
        self.path.write_text(content, encoding="utf-8")
        self.path.chmod(mode)

    def test_missing_file_disables_email(self) -> None:
        self.assertIsNone(load_email_alert_config(self.path))

    def test_valid_config_parses_and_deduplicates_recipients(self) -> None:
        self.write_config(
            "[gmail]\n"
            "username = sender@example.com\n"
            "app_password = synthetic-app-password\n"
            "recipients = first@example.com, second@example.com, first@example.com\n"
        )
        config = load_email_alert_config(self.path)
        self.assertIsNotNone(config)
        assert config is not None
        self.assertEqual(config.username, "sender@example.com")
        self.assertEqual(config.recipients, ("first@example.com", "second@example.com"))
        self.assertNotIn("synthetic-app-password", repr(config))

    def test_group_or_other_permissions_are_rejected(self) -> None:
        self.write_config(
            "[gmail]\nusername = sender@example.com\n"
            "app_password = synthetic\nrecipients = first@example.com\n",
            mode=0o640,
        )
        with self.assertRaisesRegex(AlertConfigError, "0600"):
            load_email_alert_config(self.path)

    def test_unknown_setting_is_rejected(self) -> None:
        self.write_config(
            "[gmail]\nusername = sender@example.com\n"
            "app_password = synthetic\nrecipients = first@example.com\n"
            "smtp_host = example.invalid\n"
        )
        with self.assertRaisesRegex(AlertConfigError, "only username"):
            load_email_alert_config(self.path)

    def test_invalid_recipient_is_rejected_without_echoing_value(self) -> None:
        invalid = "not-an-address"
        self.write_config(
            "[gmail]\nusername = sender@example.com\n"
            f"app_password = synthetic\nrecipients = {invalid}\n"
        )
        with self.assertRaises(AlertConfigError) as raised:
            load_email_alert_config(self.path)
        self.assertNotIn(invalid, str(raised.exception))

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links are unavailable")
    def test_symbolic_link_is_rejected(self) -> None:
        target = Path(self.temporary.name) / "target.cfg"
        target.write_text(
            "[gmail]\nusername = sender@example.com\n"
            "app_password = synthetic\nrecipients = first@example.com\n",
            encoding="utf-8",
        )
        target.chmod(0o600)
        self.path.symlink_to(target)
        with self.assertRaisesRegex(AlertConfigError, "symbolic link"):
            load_email_alert_config(self.path)


if __name__ == "__main__":
    unittest.main()
