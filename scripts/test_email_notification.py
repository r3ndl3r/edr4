#!/usr/bin/env python3
"""Send one explicit, benign Gmail SMTP configuration test message."""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from detection.base import Detection  # noqa: E402
from notifications.config import AlertConfigError, load_email_alert_config  # noqa: E402
from notifications.email import GmailEmailNotifier  # noqa: E402


def main() -> int:
    """Validate local settings and send exactly one operator-authorized email."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--alerts-config",
        type=Path,
        default=PROJECT_DIR / "alerts.cfg",
        help="local alert configuration (default: project alerts.cfg)",
    )
    parser.add_argument(
        "--send",
        action="store_true",
        help="required confirmation that one external test email may be sent",
    )
    args = parser.parse_args()
    if not args.send:
        parser.error("--send is required to transmit the test message")

    config_path = args.alerts_config
    if not config_path.is_absolute():
        config_path = PROJECT_DIR / config_path
    try:
        config = load_email_alert_config(config_path)
    except AlertConfigError as exc:
        print(f"Email configuration rejected: {exc}", file=sys.stderr)
        return 1
    if config is None:
        print("Email configuration is absent; create alerts.cfg from the example", file=sys.stderr)
        return 1

    detection = Detection(
        detector="email_configuration_test",
        severity="info",
        message="Controlled EDR4 email notification test",
        event_id=str(uuid.uuid4()),
        data={},
    )
    try:
        result = GmailEmailNotifier(config).send(detection)
    except Exception as exc:
        # SMTP errors can contain server-supplied content. Keep the diagnostic
        # useful without echoing addresses, credentials, or raw responses.
        print(f"Test email failed: {type(exc).__name__}", file=sys.stderr)
        return 1

    if result.refused:
        print(
            "Test message partially accepted: "
            f"accepted={result.accepted} refused={result.refused}"
        )
        return 1
    print(f"Test message accepted for {result.accepted} recipient(s)")
    print("SMTP acceptance does not prove final inbox delivery")
    print("No credential or recipient address was printed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
