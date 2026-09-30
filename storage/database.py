"""SQLite event storage with bounded retention."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from core.events import TelemetryEvent
from core.redaction import redact_text, redact_value


class EventDatabase:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.execute("PRAGMA journal_mode=WAL;")
        self.connection.execute("PRAGMA synchronous=NORMAL;")
        self._create_schema()

    def _create_schema(self) -> None:
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
            self.connection.rollback()
            return False

    def cleanup(self, retention_days: int, now: datetime | None = None) -> int:
        cutoff = (now or datetime.now(UTC)) - timedelta(days=retention_days)
        cursor = self.connection.execute("DELETE FROM events WHERE timestamp < ?", (cutoff.isoformat(),))
        self.connection.commit()
        return cursor.rowcount

    def count(self) -> int:
        row = self.connection.execute("SELECT COUNT(*) FROM events").fetchone()
        return int(row[0]) if row else 0

    def close(self) -> None:
        self.connection.commit()
        self.connection.close()


class PersistencePolicy:
    """Throttle periodic snapshots while preserving discrete events."""

    PERIODIC_TYPES = {"process_snapshot", "system_metrics", "network_metrics"}

    def __init__(self, metric_interval_seconds: float) -> None:
        self.metric_interval_seconds = metric_interval_seconds
        self._last_persisted: dict[str, float] = {}

    def should_persist(self, event: TelemetryEvent, monotonic_now: float) -> bool:
        if event.event_type not in self.PERIODIC_TYPES:
            return True
        last = self._last_persisted.get(event.event_type)
        if last is None or monotonic_now - last >= self.metric_interval_seconds:
            self._last_persisted[event.event_type] = monotonic_now
            return True
        return False
