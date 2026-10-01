#!/usr/bin/env python3
"""Generate one non-destructive local URL SQLi telemetry test."""

from __future__ import annotations

from urllib.parse import quote

from common import print_detection_expectation, request


def main() -> int:
    """Send one encoded local marker and verify privacy-preserving telemetry."""
    # The value is encoded before transport and is never printed by this script.
    test_value = "edr4' OR '1'='1'--"
    path = f"/rest/products/search?q={quote(test_value, safe='')}"
    print("Controlled URL SQLi telemetry test: one GET request to local Juice Shop only")
    status = request(path)
    print(f"Completed; HTTP status={status}")
    print_detection_expectation("url_sqli")
    print("The test input and response body were not printed or persisted by EDR4")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
