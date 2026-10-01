#!/usr/bin/env python3
"""Summarize recent persisted detections without dumping event payloads."""

from __future__ import annotations

import argparse
import json
import sqlite3
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = PROJECT_DIR / "data" / "edr4.db"


def main() -> int:
    """Summarize recent findings and fail when expected detector names are absent."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since-minutes", type=int, default=10, help="lookback window, 1-1440")
    parser.add_argument("--expect", action="append", default=[], help="required detector name; repeat as needed")
    args = parser.parse_args()
    if not 1 <= args.since_minutes <= 1440:
        raise SystemExit("since-minutes must be between 1 and 1440")
    if not DEFAULT_DATABASE.exists():
        raise SystemExit(f"database not found: {DEFAULT_DATABASE}")

    cutoff = (datetime.now(UTC) - timedelta(minutes=args.since_minutes)).isoformat()
    connection = sqlite3.connect(DEFAULT_DATABASE)
    rows = connection.execute(
        "SELECT timestamp, severity, data_json FROM events "
        "WHERE event_type = 'detection' AND timestamp >= ? ORDER BY timestamp",
        (cutoff,),
    ).fetchall()
    connection.close()

    counts: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    first_seen: dict[str, str] = {}
    last_seen: dict[str, str] = {}
    for timestamp, severity, data_json in rows:
        try:
            detector = str(json.loads(data_json).get("detector", "unknown"))
        except (json.JSONDecodeError, TypeError):
            detector = "malformed"
        counts[detector] += 1
        severities[severity] += 1
        first_seen.setdefault(detector, timestamp)
        last_seen[detector] = timestamp

    print(f"Detection events in last {args.since_minutes} minute(s): {len(rows)}")
    for detector in sorted(counts):
        print(f"  {detector}: count={counts[detector]} first={first_seen[detector]} last={last_seen[detector]}")
    if severities:
        print("Severities: " + ", ".join(f"{key}={value}" for key, value in sorted(severities.items())))

    missing = sorted(set(args.expect) - set(counts))
    if missing:
        print("FAIL missing expected detectors: " + ", ".join(missing))
        return 1
    if not rows:
        print("No recent detections. Confirm EDR4 was running before executing live test scripts.")
    else:
        print("Detection persistence verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
