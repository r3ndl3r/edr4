"""Shared safety guard and HTTP helper for local EDR4 tests."""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

import tomllib

BASE_URL = "http://127.0.0.1:3000"
USER_AGENT = "EDR4-Controlled-Test"
PROJECT_DIR = Path(__file__).resolve().parents[1]


def assert_local_target() -> None:
    """Refuse to run if the fixed target is no longer local Juice Shop."""
    parsed = urlsplit(BASE_URL)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("Safety check failed: target must be local loopback HTTP")
    if parsed.port != 3000:
        raise SystemExit("Safety check failed: target port must be 3000")


def bounded_count(requested: int, *, minimum: int, maximum: int) -> int:
    if not minimum <= requested <= maximum:
        raise SystemExit(f"count must be between {minimum} and {maximum}")
    return requested


def request(path: str, *, method: str = "GET", body: dict[str, str] | None = None,
            timeout: float = 5.0) -> int:
    """Make one local request and return its status without printing its body."""
    assert_local_target()
    if not path.startswith("/"):
        raise ValueError("request path must start with /")
    payload = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"User-Agent": USER_AGENT}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request_object = Request(urljoin(BASE_URL, path), data=payload, headers=headers, method=method)
    try:
        with urlopen(request_object, timeout=timeout) as response:
            response.read()
            return int(response.status)
    except HTTPError as exc:
        exc.read()
        return int(exc.code)
    except URLError as exc:
        raise SystemExit(f"Unable to reach local Juice Shop at {BASE_URL}: {exc.reason}") from exc


def run_requests(*, count: int, path: str, delay_seconds: float = 0.0,
                 method: str = "GET", body: dict[str, str] | None = None) -> Counter[int]:
    statuses: Counter[int] = Counter()
    for index in range(count):
        statuses[request(path, method=method, body=body)] += 1
        if delay_seconds > 0 and index + 1 < count:
            time.sleep(delay_seconds)
    return statuses


def status_summary(statuses: Counter[int]) -> str:
    return ", ".join(f"{status}={count}" for status, count in sorted(statuses.items()))


def print_detection_expectation(detector: str) -> None:
    """Explain live-output location and duplicate-finding cooldown."""
    cooldown: float | None = None
    try:
        with (PROJECT_DIR / "config.toml").open("rb") as handle:
            config = tomllib.load(handle)
        cooldown = float(config.get("detection", {}).get("cooldown_seconds", 60))
    except (OSError, ValueError, TypeError, tomllib.TOMLDecodeError):
        pass

    print(f"Check the running EDR4 terminal for a {detector} finding.")
    if cooldown is not None and cooldown > 0:
        print(
            f"Duplicate findings for the same rule and scope are suppressed for "
            f"{cooldown:g} seconds; wait for the cooldown before repeating this test."
        )
    print("The generated HTTP events are still collected and persisted during the cooldown.")
