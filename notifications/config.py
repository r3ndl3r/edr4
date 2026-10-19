"""Strict loading and validation for the local Gmail alert configuration.

The real ``alerts.cfg`` contains an app password and is deliberately separate
from tracked application configuration. It must be a regular, non-symlink file
owned by the current user and inaccessible to group and other users.
"""

from __future__ import annotations

import configparser
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

_REQUIRED_SECTION = "gmail"
_REQUIRED_KEYS = {"username", "app_password", "recipients"}
_EMAIL_ADDRESS = re.compile(r"^[^@\s,]+@[^@\s,]+\.[^@\s,]+$")


class AlertConfigError(ValueError):
    """Report an unsafe or invalid alert configuration without secret values."""


@dataclass(frozen=True, slots=True)
class EmailAlertConfig:
    """Validated Gmail credentials and destination addresses."""

    username: str
    app_password: str = field(repr=False)
    recipients: tuple[str, ...]


def _validate_address(value: str, label: str) -> str:
    """Validate one ordinary email address and reject header injection."""
    address = value.strip()
    if not address or "\r" in address or "\n" in address:
        raise AlertConfigError(f"{label} contains an invalid email address")
    if not _EMAIL_ADDRESS.fullmatch(address):
        raise AlertConfigError(f"{label} contains an invalid email address")
    return address


def _validate_file(path: Path) -> None:
    """Require a current-user-owned regular file with no group/other access."""
    if path.is_symlink():
        raise AlertConfigError("alerts configuration must not be a symbolic link")
    try:
        details = path.stat()
    except OSError as exc:
        raise AlertConfigError("unable to inspect alerts configuration") from exc
    if not stat.S_ISREG(details.st_mode):
        raise AlertConfigError("alerts configuration must be a regular file")
    if details.st_uid != os.geteuid():
        raise AlertConfigError("alerts configuration must be owned by the EDR user")
    if stat.S_IMODE(details.st_mode) & 0o077:
        raise AlertConfigError("alerts configuration permissions must be 0600 or stricter")


def load_email_alert_config(path: Path) -> EmailAlertConfig | None:
    """Load a strict three-value config, or return ``None`` when it is absent."""
    # Check links before existence because a broken link otherwise looks like a
    # missing optional configuration and could hide a deployment mistake.
    if path.is_symlink():
        raise AlertConfigError("alerts configuration must not be a symbolic link")
    if not path.exists():
        return None
    _validate_file(path)

    # Interpolation is disabled so a credential is always treated as literal
    # text rather than ConfigParser syntax.
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with path.open("r", encoding="utf-8") as handle:
            parser.read_file(handle)
    except (OSError, UnicodeError, configparser.Error) as exc:
        raise AlertConfigError("unable to parse alerts configuration") from exc

    if parser.defaults() or parser.sections() != [_REQUIRED_SECTION]:
        raise AlertConfigError("alerts configuration must contain only a [gmail] section")
    supplied_keys = set(parser[_REQUIRED_SECTION])
    if supplied_keys != _REQUIRED_KEYS:
        raise AlertConfigError(
            "[gmail] must contain only username, app_password, and recipients"
        )

    username = _validate_address(parser[_REQUIRED_SECTION]["username"], "username")
    app_password = parser[_REQUIRED_SECTION]["app_password"].strip()
    if not app_password or "\r" in app_password or "\n" in app_password:
        raise AlertConfigError("app_password must be present on one line")

    recipient_values = parser[_REQUIRED_SECTION]["recipients"].split(",")
    recipients: list[str] = []
    for value in recipient_values:
        recipient = _validate_address(value, "recipients")
        if recipient not in recipients:
            recipients.append(recipient)
    if not recipients:
        raise AlertConfigError("at least one recipient is required")

    return EmailAlertConfig(
        username=username,
        app_password=app_password,
        recipients=tuple(recipients),
    )
