"""Thread-safe boundary between telemetry producers and the central consumer.

The bounded queue provides backpressure so collector threads cannot grow memory
without limit when storage or detection processing slows down.
"""

from __future__ import annotations

from queue import Empty, Queue

from core.events import TelemetryEvent


class EventBus:
    """Small typed wrapper around the process-wide telemetry queue."""

    def __init__(self, maxsize: int = 10_000) -> None:
        """Create a bounded queue with the supplied maximum event count."""
        self._queue: Queue[TelemetryEvent] = Queue(maxsize=maxsize)

    def publish(self, event: TelemetryEvent) -> None:
        """Queue an event, waiting briefly for consumer backpressure to clear."""
        # A finite timeout lets a collector report queue congestion instead of
        # becoming permanently blocked when the consumer fails.
        self._queue.put(event, timeout=2)

    def get(self, timeout: float = 1.0) -> TelemetryEvent:
        """Return the next event or raise ``queue.Empty`` after the timeout."""
        return self._queue.get(timeout=timeout)

    def task_done(self) -> None:
        """Mark the most recently consumed queue item as processed."""
        self._queue.task_done()

    def empty(self) -> bool:
        """Return whether the queue currently contains no events."""
        return self._queue.empty()

    @staticmethod
    def empty_exception() -> type[Empty]:
        """Expose the queue-empty exception without leaking queue internals."""
        return Empty
