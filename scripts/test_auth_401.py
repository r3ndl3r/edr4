#!/usr/bin/env python3
"""Generate bounded authentication-like 401 responses using dummy values."""

from __future__ import annotations

import argparse

from common import bounded_count, print_detection_expectation, run_requests, status_summary

_DUMMY_LOGIN = {
    "email": "edr4-controlled-test@example.invalid",
    "password": "intentionally-invalid-test-value",
}


def main() -> int:
    """Generate bounded dummy failures and report expected passive telemetry."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=5, help="attempt count, 1-10 (default: 5)")
    parser.add_argument("--delay", type=float, default=0.2, help="delay between attempts in seconds")
    args = parser.parse_args()
    count = bounded_count(args.count, minimum=1, maximum=10)
    if not 0 <= args.delay <= 2:
        raise SystemExit("delay must be between 0 and 2 seconds")

    print(f"Controlled auth telemetry test: {count} dummy login attempts to local Juice Shop only")
    statuses = run_requests(
        count=count,
        path="/rest/user/login",
        method="POST",
        body=_DUMMY_LOGIN,
        delay_seconds=args.delay,
    )
    print(f"Completed; {status_summary(statuses)}")
    if statuses.get(401, 0) < count:
        print("WARNING: not every request returned 401; inspect Juice Shop behavior and EDR output")
        return 1
    print_detection_expectation("repeated_auth_401")
    print("Dummy request values were not printed; EDR does not ingest request bodies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
