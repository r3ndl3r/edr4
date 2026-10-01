"""Rotation-aware Morgan access-log parsing and collection.

Responsibilities:
- Follow the newest Juice Shop ``access.log.*`` file across rotation.
- Normalize HTTP metadata without retaining query values.
- Inspect bounded URL content transiently for SQLi indicator categories.

The parser is a privacy boundary: raw query values and SQLi-like path content
must not enter the event queue, console, or SQLite database.
"""

from __future__ import annotations

import glob
import logging
import os
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO
from urllib.parse import unquote_plus, urlsplit

from collectors.base import BaseCollector
from core.event_bus import EventBus
from core.events import TelemetryEvent, create_event
from core.redaction import redact_text

_COMBINED_RE = re.compile(
    r'^(?P<source>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<target>\S+) HTTP/(?P<http_version>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\d+|-) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"$'
)
_SAFE_QUERY_KEY = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_SENSITIVE_PATH_VALUE = re.compile(
    r"(?i)(/(?:password|passwd|token|access_token|refresh_token|authorization|api[_-]?key|secret|credential|session)/)[^/]+"
)
_SQLI_PATTERNS = (
    ("union_select", re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE)),
    (
        "boolean_expression",
        re.compile(
            r"\b(?:or|and)\b\s+['\"]?[a-z0-9_.-]+['\"]?\s*=\s*['\"]?[a-z0-9_.-]+['\"]?",
            re.IGNORECASE,
        ),
    ),
    (
        "stacked_statement",
        re.compile(
            r";\s*(?:select|insert|update|delete|drop|alter|create|exec(?:ute)?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "time_delay",
        re.compile(r"\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b", re.IGNORECASE),
    ),
    (
        "schema_enumeration",
        re.compile(r"\b(?:information_schema|sqlite_master|pg_catalog)\b", re.IGNORECASE),
    ),
)
_SQL_COMMENT = re.compile(r"(?:--(?:\s|$)|/\*|\*/|#)")
_SQL_KEYWORD = re.compile(
    r"\b(?:select|union|insert|update|delete|drop|alter|create|exec(?:ute)?)\b",
    re.IGNORECASE,
)
_MAX_SQLI_INSPECTION_LENGTH = 4_096


def _decode_for_sqli_inspection(value: str) -> str:
    """Decode a bounded URL component transiently without returning it as telemetry."""
    # Decode twice to catch ordinary and double URL encoding. The length cap
    # limits parser work and the decoded text never leaves this helper chain.
    decoded = value[:_MAX_SQLI_INSPECTION_LENGTH]
    for _ in range(2):
        candidate = unquote_plus(decoded)
        if candidate == decoded:
            break
        decoded = candidate[:_MAX_SQLI_INSPECTION_LENGTH]
    return re.sub(r"[\x00-\x20]+", " ", decoded)


def _sqli_categories(value: str) -> list[str]:
    """Return indicator names only; never return inspected URL content."""
    if not value:
        return []
    decoded = _decode_for_sqli_inspection(value)
    categories = [name for name, pattern in _SQLI_PATTERNS if pattern.search(decoded)]
    comment = _SQL_COMMENT.search(decoded)
    quote_comment = re.search(r"['\"]\s*(?:--|#|/\*)", decoded)
    # A comment marker alone is common in legitimate text. Require another SQL
    # signal or a quote/comment combination before treating it as suspicious.
    if comment and (categories or quote_comment or _SQL_KEYWORD.search(decoded)):
        categories.append("sql_comment")
    return sorted(set(categories))


def _url_sqli_metadata(path: str, query: str) -> tuple[list[str], list[str]]:
    """Derive safe SQLi categories and input locations from URL components."""
    categories: set[str] = set()
    locations: list[str] = []
    for location, value in (("path", path), ("query", query)):
        observed = _sqli_categories(value)
        if observed:
            locations.append(location)
            categories.update(observed)
    return sorted(categories), locations


def _query_keys(query: str) -> list[str]:
    """Extract key names without retaining or decoding query values."""
    keys: list[str] = []
    for component in query.split("&"):
        if not component:
            continue
        # partition() extracts only the name before the first '='. The value is
        # intentionally never appended to telemetry or diagnostic output.
        raw_key = component.partition("=")[0]
        try:
            key = unquote_plus(raw_key)
        except Exception:
            key = "[invalid_key]"
        if not _SAFE_QUERY_KEY.fullmatch(key):
            key = "[unusual_key]"
        if key not in keys:
            keys.append(key)
    return keys[:50]


def _safe_referrer(referrer: str) -> str:
    """Remove query data and redact suspicious path content from a referrer."""
    if not referrer or referrer == "-":
        return referrer
    try:
        parsed = urlsplit(referrer)
        path = "/[REDACTED_SQLI_INPUT]" if _sqli_categories(parsed.path) else _safe_path(parsed.path)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}{path}"
        return path or "-"
    except ValueError:
        return "[invalid_referrer]"


def _safe_path(path: str) -> str:
    """Redact obvious secret-bearing path segments and cap path length."""
    path = _SENSITIVE_PATH_VALUE.sub(lambda match: f"{match.group(1)}[REDACTED]", path)
    return redact_text(path, max_length=1_024)


def parse_combined_line(line: str) -> TelemetryEvent | None:
    """Parse one Morgan combined line without preserving raw query values."""
    match = _COMBINED_RE.match(line.rstrip("\r\n"))
    if not match:
        return None
    fields = match.groupdict()
    try:
        observed = datetime.strptime(fields["timestamp"], "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC).isoformat()
        status = int(fields["status"])
        response_size = None if fields["size"] == "-" else int(fields["size"])
        parsed_target = urlsplit(fields["target"])
    except (ValueError, OverflowError):
        return None

    sqli_categories, sqli_locations = _url_sqli_metadata(
        parsed_target.path, parsed_target.query
    )
    path = (
        "/[REDACTED_SQLI_INPUT]"
        if "path" in sqli_locations
        else _safe_path(parsed_target.path or "/")
    )
    keys = _query_keys(parsed_target.query)
    severity = "error" if status >= 500 else "warning" if status >= 400 else "info"
    source = fields["source"]
    message = f'{fields["method"]} {path} -> {status} src={source}'
    return create_event(
        timestamp=observed,
        event_type="http_request",
        source="morgan",
        severity=severity,
        message=message,
        data={
            "source_ip": source,
            "http_method": fields["method"],
            "request_uri": path,
            "path": path,
            "query_present": bool(parsed_target.query),
            "query_keys": keys,
            "sqli_suspected": bool(sqli_categories),
            "sqli_indicator_categories": sqli_categories,
            "sqli_input_locations": sqli_locations,
            "http_version": fields["http_version"],
            "response_status": status,
            "response_size": response_size,
            "referrer": _safe_referrer(fields["referrer"]),
            "user_agent": redact_text(fields["user_agent"], max_length=512),
        },
    )


class MorganCollector(BaseCollector):
    """Tail the active Morgan file and survive replacement or date rotation."""

    def __init__(
        self,
        event_bus: EventBus,
        stop_event: threading.Event,
        logger: logging.Logger,
        path_pattern: str,
        start_at_end: bool = True,
    ) -> None:
        """Configure the log glob and whether initial history should be skipped."""
        super().__init__("morgan", event_bus, stop_event, logger)
        self.path_pattern = path_pattern
        self.start_at_end = start_at_end
        self._file: TextIO | None = None
        self._path: Path | None = None
        self._inode: int | None = None

    def _newest(self) -> Path | None:
        """Return the most recently modified regular file matching the glob."""
        candidates = [Path(item) for item in glob.glob(self.path_pattern)]
        candidates = [item for item in candidates if item.is_file()]
        return max(candidates, key=lambda item: item.stat().st_mtime_ns) if candidates else None

    def _open(self, path: Path, at_end: bool) -> None:
        """Open a candidate log and record identity needed for rotation checks."""
        self._close()
        self._file = path.open("r", encoding="utf-8", errors="replace")
        if at_end:
            # Starting at EOF prevents replaying old traffic every time EDR4
            # starts. Rotated replacement files are read from their beginning.
            self._file.seek(0, os.SEEK_END)
        stat = path.stat()
        self._path = path
        self._inode = stat.st_ino
        self.logger.debug("[MORGAN] following %s", path)

    def _close(self) -> None:
        """Close the active file and clear its path and inode state."""
        if self._file is not None:
            self._file.close()
        self._file = None
        self._path = None
        self._inode = None

    def _rotated(self, newest: Path | None) -> bool:
        """Detect path replacement, inode change, or truncation."""
        if newest is None or self._path is None or self._file is None:
            return newest != self._path
        try:
            stat = self._path.stat()
            # Rotation may change the filename/inode, while copy-truncate keeps
            # the path but makes the file smaller than our current offset.
            return newest != self._path or stat.st_ino != self._inode or stat.st_size < self._file.tell()
        except FileNotFoundError:
            return True

    def run(self) -> None:
        """Follow appended lines until shutdown while recovering from I/O errors."""
        initial = True
        while not self.stop_event.is_set():
            try:
                newest = self._newest()
                if self._file is None and newest is not None:
                    self._open(newest, at_end=self.start_at_end and initial)
                    initial = False
                elif self._rotated(newest) and newest is not None:
                    self._open(newest, at_end=False)

                if self._file is None:
                    self.wait(1.0)
                    continue
                line = self._file.readline()
                if not line:
                    self.wait(0.5)
                    continue
                event = parse_combined_line(line)
                if event is not None:
                    self.publish(event)
                else:
                    self.logger.debug("[MORGAN] skipped malformed access-log line")
            except Exception as exc:
                self.logger.error("[MORGAN] collector error: %s", exc)
                self._close()
                self.wait(2.0)
        self._close()
