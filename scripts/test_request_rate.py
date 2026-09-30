#!/usr/bin/env python3
"""Generate a small local burst for request-rate detector validation."""

from __future__ import annotations

import argparse
import time

from common import bounded_count, print_detection_expectation, run_requests, status_summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=35, help="request count, 1-60 (default: 35)")
    parser.add_argument("--delay", type=float, default=0.03, help="delay between requests in seconds")
    args = parser.parse_args()
    count = bounded_count(args.count, minimum=1, maximum=60)
    if not 0 <= args.delay <= 1:
        raise SystemExit("delay must be between 0 and 1 second")

    path = "/rest/products/search?q=edr4-rate-test"
    print(f"Controlled request-rate test: {count} GET requests to a logged local endpoint")
    started = time.monotonic()
    statuses = run_requests(count=count, path=path, delay_seconds=args.delay)
    elapsed = max(time.monotonic() - started, 0.001)
    print(f"Completed in {elapsed:.2f}s ({count / elapsed:.1f} requests/s); {status_summary(statuses)}")
    print_detection_expectation("request_rate (global and per-source)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
