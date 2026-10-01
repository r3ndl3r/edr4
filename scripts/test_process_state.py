#!/usr/bin/env python3
"""Safely validate process-state rules with synthetic events only."""

from __future__ import annotations

import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from core.events import create_event  # noqa: E402
from detection.rules import ProcessStateDetector  # noqa: E402


def current_main_pid() -> int:
    """Read the live service MainPID without signaling or modifying the process."""
    completed = subprocess.run(
        ["systemctl", "show", "juice-shop.service", "-p", "MainPID", "--value"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    try:
        return int(completed.stdout.strip())
    except ValueError as exc:
        raise SystemExit("Unable to determine the live Juice Shop MainPID") from exc


def process_event(timestamp: datetime, pid: int, status: str):
    """Build one synthetic process event for isolated detector validation."""
    return create_event(
        timestamp=timestamp.isoformat(),
        event_type="process_snapshot",
        source="process",
        message="synthetic process-state validation event",
        data={"pid": pid, "status": status},
    )


def main() -> int:
    """Exercise process-state transitions entirely in memory."""
    live_pid = current_main_pid()
    if live_pid <= 0:
        raise SystemExit("juice-shop.service has no active MainPID")
    detector = ProcessStateDetector(
        abnormal_states=["dead", "zombie", "stopped", "tracing-stop"],
        cooldown_seconds=0,
    )
    base = datetime.now(UTC)
    detector.process(process_event(base, live_pid, "sleeping"))
    findings = []
    findings.extend(detector.process(process_event(base + timedelta(seconds=1), live_pid + 100_000, "sleeping")))
    findings.extend(detector.process(process_event(base + timedelta(seconds=2), live_pid + 100_000, "zombie")))
    unavailable = create_event(
        timestamp=(base + timedelta(seconds=3)).isoformat(),
        event_type="service_status",
        source="process",
        severity="warning",
        message="synthetic unavailable event",
        data={"service": "juice-shop.service", "available": False},
    )
    findings.extend(detector.process(unavailable))

    print(f"Live Juice Shop PID read successfully: {live_pid}")
    print("No process was signalled, stopped, restarted, or modified")
    for finding in findings:
        print(f"PASS {finding.detector}: {finding.data.get('change')} severity={finding.severity}")
    expected = {"pid", "status", "service_unavailable"}
    observed = {str(finding.data.get("change")) for finding in findings}
    if observed != expected:
        print(f"FAIL expected changes={sorted(expected)} observed={sorted(observed)}")
        return 1
    print("Process-state detector synthetic validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
