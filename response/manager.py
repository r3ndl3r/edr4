"""Deliberately inactive response orchestration boundary.

The manager accepts findings so the pipeline shape is stable, but it never
blocks traffic, alters files, changes services, or terminates processes.
"""

from __future__ import annotations

from detection.base import Detection


class ResponseManager:
    """No-op response manager retained for future controlled development."""

    def __init__(self, enabled: bool = False) -> None:
        """Record requested state without enabling active response behavior."""
        self.enabled = enabled

    def process(self, detection: Detection) -> None:
        """Intentionally perform no active response."""
        return None
