"""Inactive response manager skeleton."""

from __future__ import annotations

from detection.base import Detection


class ResponseManager:
    def __init__(self, enabled: bool = False) -> None:
        self.enabled = enabled

    def process(self, detection: Detection) -> None:
        """Intentionally perform no active response."""
        return None
