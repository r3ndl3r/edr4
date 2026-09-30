"""Best-effort privacy controls applied before display and persistence."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

MAX_TEXT_LENGTH = 2_048
REDACTED = "[REDACTED]"

_SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|token|access_token|refresh_token|authorization|cookie|api[_-]?key|secret|credential|session)",
    re.IGNORECASE,
)
_INLINE_SECRET = re.compile(
    r"(?i)\b(password|passwd|token|access_token|refresh_token|authorization|cookie|api[_-]?key|secret|credential|session)"
    r"\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")


def redact_text(value: str, max_length: int = MAX_TEXT_LENGTH) -> str:
    """Redact obvious inline secrets and bound text size.

    This is intentionally a secondary safeguard. Collectors avoid ingesting
    request bodies, cookie/auth headers, and raw query values in the first place.
    """
    text = _INLINE_SECRET.sub(lambda match: f"{match.group(1)}={REDACTED}", value)
    text = _BEARER.sub(f"Bearer {REDACTED}", text)
    if len(text) > max_length:
        return text[:max_length] + "...[TRUNCATED]"
    return text


def redact_value(value: Any, key: str | None = None) -> Any:
    """Recursively redact a JSON-compatible value."""
    if key is not None and _SENSITIVE_KEY.search(key):
        return REDACTED
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {str(k): redact_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [redact_value(item) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(str(value))
