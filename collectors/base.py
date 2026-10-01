"""Shared thread lifecycle and event publication for telemetry collectors.

Collectors inherit this class to publish normalized events through the central
queue while sharing one cooperative shutdown signal.
"""

from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod

from core.event_bus import EventBus
from core.events import TelemetryEvent


class BaseCollector(threading.Thread, ABC):
    """Base class that isolates a collector in its own daemon thread."""

    def __init__(self, name: str, event_bus: EventBus, stop_event: threading.Event, logger: logging.Logger) -> None:
        """Initialize collector identity, queue integration, and shutdown state."""
        super().__init__(name=f"collector-{name}", daemon=True)
        self.collector_name = name
        self.event_bus = event_bus
        self.stop_event = stop_event
        self.logger = logger

    def publish(self, event: TelemetryEvent) -> None:
        """Publish one event while containing queue failures within this collector."""
        try:
            self.event_bus.publish(event)
        except Exception as exc:
            self.logger.error("[%s] unable to publish event: %s", self.collector_name.upper(), exc)

    def wait(self, seconds: float) -> bool:
        """Wait interruptibly; return true when shutdown was requested."""
        return self.stop_event.wait(seconds)

    @abstractmethod
    def run(self) -> None:
        """Run until the shared stop event is set."""

    def stop(self) -> None:
        """Request cooperative shutdown for all collectors sharing the event."""
        self.stop_event.set()
