"""Thread-safe event queue."""

from __future__ import annotations

from queue import Empty, Queue

from core.events import TelemetryEvent


class EventBus:
    def __init__(self, maxsize: int = 10_000) -> None:
        self._queue: Queue[TelemetryEvent] = Queue(maxsize=maxsize)

    def publish(self, event: TelemetryEvent) -> None:
        self._queue.put(event, timeout=2)

    def get(self, timeout: float = 1.0) -> TelemetryEvent:
        return self._queue.get(timeout=timeout)

    def task_done(self) -> None:
        self._queue.task_done()

    def empty(self) -> bool:
        return self._queue.empty()

    @staticmethod
    def empty_exception() -> type[Empty]:
        return Empty
