"""Non-blocking queue and isolated worker for outbound email notifications."""

from __future__ import annotations

import logging
import queue
import threading

from detection.base import Detection
from notifications.email import EmailDeliveryResult, GmailEmailNotifier

_SEVERITY = {"debug": 10, "info": 20, "warning": 30, "error": 40, "critical": 50}


class NotificationManager:
    """Send warning-or-higher findings without blocking telemetry processing."""

    def __init__(
        self,
        notifier: GmailEmailNotifier | None,
        logger: logging.Logger,
        *,
        queue_size: int = 100,
        retry_delay_seconds: float = 2.0,
    ) -> None:
        """Configure an optional bounded worker with one delivery retry."""
        self.notifier = notifier
        self.logger = logger
        self.retry_delay_seconds = max(0.0, retry_delay_seconds)
        self._queue: queue.Queue[Detection] = queue.Queue(maxsize=max(1, queue_size))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def enabled(self) -> bool:
        """Return whether a valid notifier is configured."""
        return self.notifier is not None

    @property
    def recipient_count(self) -> int:
        """Return the configured recipient count without exposing addresses."""
        return self.notifier.recipient_count if self.notifier is not None else 0

    def start(self) -> None:
        """Start the email worker when notification delivery is enabled."""
        if not self.enabled or self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run,
            name="email-notifications",
            daemon=True,
        )
        self._thread.start()

    def submit(self, detection: Detection) -> bool:
        """Queue a warning-or-higher finding without blocking the caller."""
        if not self.enabled or _SEVERITY.get(detection.severity.lower(), 0) < _SEVERITY["warning"]:
            return False
        try:
            self._queue.put_nowait(detection)
            return True
        except queue.Full:
            self.logger.warning(
                "[EMAIL] notification queue full; finding dropped detector=%s",
                detection.detector,
            )
            return False

    def _deliver(self, detection: Detection) -> None:
        """Attempt delivery twice while containing all SMTP failures."""
        assert self.notifier is not None
        for attempt in (1, 2):
            try:
                result = self.notifier.send(detection)
                self._report_result(detection, result)
                return
            except Exception as exc:  # SMTP/network isolation boundary
                if attempt == 1 and not self._stop.wait(self.retry_delay_seconds):
                    continue
                # Exception text can contain server responses or addresses, so
                # log only its class rather than interpolating the raw message.
                self.logger.error(
                    "[EMAIL] delivery failed detector=%s error_type=%s attempts=%d",
                    detection.detector,
                    type(exc).__name__,
                    attempt,
                )
                return

    def _report_result(self, detection: Detection, result: EmailDeliveryResult) -> None:
        """Log delivery counts without exposing recipient addresses."""
        if result.refused == 0:
            self.logger.info(
                "[EMAIL] alert accepted detector=%s recipients=%d",
                detection.detector,
                result.accepted,
            )
        elif result.accepted:
            # Retrying a partial result could duplicate mail for recipients
            # that Gmail already accepted during the first submission.
            self.logger.warning(
                "[EMAIL] alert partially accepted detector=%s accepted=%d refused=%d",
                detection.detector,
                result.accepted,
                result.refused,
            )
        else:
            self.logger.error(
                "[EMAIL] all recipients refused detector=%s recipients=%d",
                detection.detector,
                result.attempted,
            )

    def _run(self) -> None:
        """Consume queued findings until cooperative shutdown is requested."""
        while not self._stop.is_set():
            try:
                detection = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._deliver(detection)
            finally:
                self._queue.task_done()

    def stop(self) -> None:
        """Stop accepting work and wait briefly for an active SMTP operation."""
        if self._thread is None:
            return
        self._stop.set()

        dropped = 0
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break
            else:
                dropped += 1
                self._queue.task_done()
        if dropped:
            self.logger.warning("[EMAIL] shutdown discarded %d queued notification(s)", dropped)

        # One in-progress SMTP operation is allowed slightly longer than its
        # configured network timeout. The daemon boundary still prevents a
        # broken remote server from hanging EDR shutdown forever.
        timeout = (self.notifier.timeout + 2.0) if self.notifier is not None else 2.0
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            self.logger.warning("[EMAIL] worker did not stop before shutdown timeout")
