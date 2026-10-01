"""Future response-action contract.

No active response implementation is provided; this interface reserves a
stable boundary for a later explicitly authorized implementation round.
"""

from __future__ import annotations

from typing import Protocol

from detection.base import Detection


class ResponseAction(Protocol):
    """Structural interface for a future response action."""

    def process(self, detection: Detection) -> None:
        """Receive a detection without defining any active behavior yet."""
        ...
