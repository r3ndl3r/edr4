"""SQLite persistence, indexing, metric throttling, and bounded retention.

Collectors never write here directly. The central consumer applies persistence
policy and this module re-applies redaction before crossing the storage boundary.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from core.events import TelemetryEvent
from core.redaction import redact_text, redact_value


class EventDatabase:
    """Own the SQLite connection and normalized event table lifecycle."""

    def __init__(self, path: Path) -> None:
        """Open the database, enable WAL mode, and ensure the schema exists."""
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        # WAL lets another process read reports while the EDR continues to
        # write. This is useful when a team member inspects the live database.
        self.connection.execute("PRAGMA journal_mode=WAL;")
        self.connection.execute("PRAGMA synchronous=NORMAL;")
        self._create_schema()

    def _create_schema(self) -> None:
        """Create the events table and query indexes idempotently."""
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                host TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT,
                data_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
            CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
            """
        )
        self.connection.commit()

    def insert_event(self, event: TelemetryEvent) -> bool:
        """Insert one event. Return False when event_id already exists."""
        # Redact again at the storage boundary. Collectors should already emit
        # safe data, but this protects SQLite if a future collector makes a
        # mistake and passes a sensitive field through.
        safe_data = redact_value(event.data)
        try:
            self.connection.execute(
                """
                INSERT INTO events
                    (event_id, timestamp, host, event_type, source, severity, message, data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.timestamp,
                    event.host,
                    event.event_type,
                    event.source,
                    event.severity,
                    redact_text(event.message, max_length=512),
                    json.dumps(safe_data, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                ),
            )
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            # event_id is UNIQUE. A duplicate event is harmless, so report it
            # to the caller instead of terminating the consumer loop.
            self.connection.rollback()
            return False

    def cleanup(self, retention_days: int, now: datetime | None = None) -> int:
        """Delete events older than the retention boundary and return the count."""
        cutoff = (now or datetime.now(UTC)) - timedelta(days=retention_days)
        cursor = self.connection.execute("DELETE FROM events WHERE timestamp < ?", (cutoff.isoformat(),))
        self.connection.commit()
        return cursor.rowcount

    def count(self) -> int:
        """Return the current number of persisted events."""
        row = self.connection.execute("SELECT COUNT(*) FROM events").fetchone()
        return int(row[0]) if row else 0

    def close(self) -> None:
        """Commit pending work and close the owned SQLite connection."""
        self.connection.commit()
        self.connection.close()


class PersistencePolicy:
    """Throttle periodic snapshots while preserving discrete events."""

    PERIODIC_TYPES = {"process_snapshot", "system_metrics", "network_metrics"}

    def __init__(self, metric_interval_seconds: float) -> None:
        """Configure the minimum persistence interval for each metric type."""
        self.metric_interval_seconds = metric_interval_seconds
        self._last_persisted: dict[str, float] = {}

    def should_persist(self, event: TelemetryEvent, monotonic_now: float) -> bool:
        """Persist discrete events always and periodic metrics at the set cadence."""
        if event.event_type not in self.PERIODIC_TYPES:
            # HTTP and journal records describe individual occurrences; unlike
            # recurring metric samples, every one may be significant.
            return True
        # Each metric type has its own timer. Storing system_metrics therefore
        # does not delay the next process_snapshot or network_metrics record.
        last = self._last_persisted.get(event.event_type)
        if last is None or monotonic_now - last >= self.metric_interval_seconds:
            self._last_persisted[event.event_type] = monotonic_now
            return True
        return False
