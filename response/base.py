"""Response action interface definitions."""

from __future__ import annotations

from typing import Protocol

from detection.base import Detection


class ResponseAction(Protocol):
    def process(self, detection: Detection) -> None: ...
