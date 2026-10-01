"""Unit tests for SQLite persistence, deduplication, retention, and redaction."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from core.events import create_event
from storage.database import EventDatabase


class EventDatabaseTests(unittest.TestCase):
    """Exercise each database test in an isolated temporary directory."""

    def setUp(self) -> None:
        """Create a fresh database so tests cannot affect live EDR data."""
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "nested" / "edr4.db"
        self.database = EventDatabase(self.path)

    def tearDown(self) -> None:
        """Close SQLite before removing the temporary test directory."""
        self.database.close()
        self.temporary.cleanup()

    def test_database_creation_and_json_persistence(self) -> None:
        event = create_event(
            event_type="http_request", source="morgan", message="GET / -> 200",
            data={"response_status": 200, "query_keys": ["q"]},
        )
        self.assertTrue(self.database.insert_event(event))
        self.assertTrue(self.path.exists())
        row = self.database.connection.execute(
            "SELECT event_id, data_json FROM events WHERE event_id = ?", (event.event_id,)
        ).fetchone()
        self.assertEqual(row[0], event.event_id)
        self.assertEqual(json.loads(row[1])["response_status"], 200)

    def test_unique_event_id(self) -> None:
        event = create_event(event_type="journal_event", source="journal", message="test")
        self.assertTrue(self.database.insert_event(event))
        self.assertFalse(self.database.insert_event(event))
        self.assertEqual(self.database.count(), 1)

    def test_retention_cleanup(self) -> None:
        now = datetime.now(UTC)
        old = create_event(
            timestamp=(now - timedelta(days=4)).isoformat(),
            event_type="journal_event", source="journal", message="old",
        )
        recent = create_event(
            timestamp=(now - timedelta(hours=1)).isoformat(),
            event_type="journal_event", source="journal", message="recent",
        )
        self.database.insert_event(old)
        self.database.insert_event(recent)
        self.assertEqual(self.database.cleanup(3, now=now), 1)
        self.assertEqual(self.database.count(), 1)

    def test_storage_redacts_sensitive_keys(self) -> None:
        event = create_event(
            event_type="journal_event", source="journal", message="safe",
            data={"password": "must-not-survive", "nested": {"token": "secret"}},
        )
        self.database.insert_event(event)
        data_json = self.database.connection.execute(
            "SELECT data_json FROM events WHERE event_id = ?", (event.event_id,)
        ).fetchone()[0]
        self.assertNotIn("must-not-survive", data_json)
        self.assertNotIn('"secret"', data_json)


if __name__ == "__main__":
    unittest.main()
