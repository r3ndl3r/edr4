#!/usr/bin/env python3
"""Generate bounded local 5xx responses for status-anomaly validation."""

from __future__ import annotations

import argparse

from common import bounded_count, print_detection_expectation, run_requests, status_summary


def main() -> int:
    """Generate bounded local error responses for status-ratio validation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=20, help="request count, 1-30 (default: 20)")
    parser.add_argument("--delay", type=float, default=0.1, help="delay between requests in seconds")
    args = parser.parse_args()
    count = bounded_count(args.count, minimum=1, maximum=30)
    if not 0 <= args.delay <= 2:
        raise SystemExit("delay must be between 0 and 2 seconds")

    print(f"Controlled status test: {count} requests to a missing local API route")
    statuses = run_requests(
        count=count,
        path="/api/EDR4MissingResource",
        delay_seconds=args.delay,
    )
    print(f"Completed; {status_summary(statuses)}")
    server_errors = sum(value for status, value in statuses.items() if 500 <= status <= 599)
    if server_errors == 0:
        print("WARNING: this Juice Shop deployment did not return 5xx for the test route")
        return 1
    print_detection_expectation("status_anomaly for an elevated 5xx ratio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
