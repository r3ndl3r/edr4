#!/usr/bin/env python3
"""EDR4 telemetry prototype entry point."""

from __future__ import annotations

import argparse
import logging
import signal
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Any

try:
    import psutil  # noqa: F401 - fail early with an actionable message
except ImportError:
    print("psutil is required. Activate .venv or run .venv/bin/python main.py.", file=sys.stderr)
    raise SystemExit(2)

from collectors.base import BaseCollector
from collectors.journal import JournalCollector
from collectors.morgan import MorganCollector
from collectors.process import ProcessCollector
from collectors.system import SystemCollector
from core.config import load_config
from core.event_bus import EventBus
from core.logging_setup import configure_logging, log_event
from detection.base import detection_to_event
from detection.engine import DetectionEngine
from response.manager import ResponseManager
from storage.database import EventDatabase, PersistencePolicy

PROJECT_DIR = Path(__file__).resolve().parent


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="EDR4 telemetry prototype")
    parser.add_argument("--config", type=Path, default=PROJECT_DIR / "config.toml")
    parser.add_argument("--verbose", action="store_true", help="show structured event details")
    return parser.parse_args()


def _enabled(config: dict[str, Any], collector: str) -> bool:
    return bool(config.get("collectors", {}).get(collector, {}).get("enabled", False))


def _build_collectors(
    config: dict[str, Any], bus: EventBus, stop_event: threading.Event, logger: logging.Logger
) -> list[BaseCollector]:
    general = config["general"]
    collector_config = config["collectors"]
    interval = float(general.get("poll_interval_seconds", 5))
    service = str(general.get("service", "juice-shop.service"))
    collectors: list[BaseCollector] = []
    if _enabled(config, "morgan"):
        settings = collector_config["morgan"]
        collectors.append(MorganCollector(
            bus, stop_event, logger,
            path_pattern=str(settings["path"]),
            start_at_end=bool(settings.get("start_at_end", True)),
        ))
    if _enabled(config, "journal"):
        settings = collector_config["journal"]
        collectors.append(JournalCollector(
            bus, stop_event, logger, service=service,
            retry_seconds=float(settings.get("retry_seconds", 5)),
        ))
    if _enabled(config, "process"):
        collectors.append(ProcessCollector(bus, stop_event, logger, service=service, poll_interval=interval))
    if _enabled(config, "system"):
        collectors.append(SystemCollector(
            bus, stop_event, logger, poll_interval=interval,
            interface=str(general.get("network_interface", "ens33")),
        ))
    return collectors


def _startup_summary(
    logger: logging.Logger,
    config: dict[str, Any],
    database_path: Path,
) -> None:
    logger.info("EDR4 Telemetry Prototype")
    logger.info("Database: %s", database_path)
    logger.info("Collectors:")
    names = (("morgan", "Morgan HTTP"), ("journal", "Juice Shop Journal"),
             ("process", "Juice Shop Process"), ("system", "System/Network"))
    for key, label in names:
        logger.info("  [%s] %s", "ON" if _enabled(config, key) else "OFF", label)
    logger.info(
        "Detection: %s",
        "enabled (passive)" if config.get("detection", {}).get("enabled") else "disabled",
    )
    logger.info("Response: %s", "enabled" if config.get("response", {}).get("enabled") else "disabled")
    logger.info("Press Ctrl+C to stop.")


def run() -> int:
    args = _arguments()
    try:
        config = load_config(args.config)
    except (OSError, ValueError) as exc:
        print(f"Unable to load configuration: {exc}", file=sys.stderr)
        return 2

    verbose = bool(args.verbose or config.get("console", {}).get("verbose", False))
    logger = configure_logging(verbose)
    stop_event = threading.Event()
    bus = EventBus()

    storage_config = config.get("storage", {})
    database_path = Path(str(storage_config.get("path", "data/edr4.db")))
    if not database_path.is_absolute():
        database_path = PROJECT_DIR / database_path
    database: EventDatabase | None = None
    if storage_config.get("enabled", True):
        try:
            database = EventDatabase(database_path)
        except sqlite3.Error as exc:
            logger.error("[STORAGE] database initialization failed: %s", exc)
            return 1

    policy = PersistencePolicy(float(storage_config.get("metric_persist_interval_seconds", 15)))
    retention_days = int(storage_config.get("retention_days", 3))
    cleanup_interval = float(storage_config.get("cleanup_interval_seconds", 3600))
    next_cleanup = time.monotonic() + cleanup_interval
    if database is not None:
        try:
            deleted = database.cleanup(retention_days)
            logger.debug("[STORAGE] startup retention cleanup removed %d events", deleted)
        except sqlite3.Error as exc:
            logger.error("[STORAGE] startup cleanup failed: %s", exc)

    detection = DetectionEngine(config.get("detection", {}), logger)
    response = ResponseManager(bool(config.get("response", {}).get("enabled", False)))
    collectors = _build_collectors(config, bus, stop_event, logger)

    def request_shutdown(signum: int, _frame: object) -> None:
        if not stop_event.is_set():
            logger.info("EDR4 shutting down... signal=%s", signum)
            stop_event.set()
            for collector in collectors:
                collector.stop()

    signal.signal(signal.SIGINT, request_shutdown)
    signal.signal(signal.SIGTERM, request_shutdown)
    _startup_summary(logger, config, database_path)
    for collector in collectors:
        collector.start()

    try:
        while not stop_event.is_set() or any(collector.is_alive() for collector in collectors) or not bus.empty():
            try:
                event = bus.get(timeout=0.5)
            except bus.empty_exception():
                continue
            try:
                log_event(logger, event, verbose)
                if database is not None and policy.should_persist(event, time.monotonic()):
                    try:
                        database.insert_event(event)
                    except sqlite3.Error as exc:
                        logger.error("[STORAGE] insert failed: %s", exc)
                for finding in detection.process(event):
                    detection_event = detection_to_event(finding)
                    log_event(logger, detection_event, verbose)
                    if database is not None:
                        try:
                            database.insert_event(detection_event)
                        except sqlite3.Error as exc:
                            logger.error("[STORAGE] detection insert failed: %s", exc)
                    response.process(finding)
            finally:
                bus.task_done()

            if database is not None and time.monotonic() >= next_cleanup:
                try:
                    deleted = database.cleanup(retention_days)
                    logger.debug("[STORAGE] periodic cleanup removed %d events", deleted)
                except sqlite3.Error as exc:
                    logger.error("[STORAGE] periodic cleanup failed: %s", exc)
                next_cleanup = time.monotonic() + cleanup_interval
    except KeyboardInterrupt:
        request_shutdown(signal.SIGINT, None)
    finally:
        stop_event.set()
        for collector in collectors:
            collector.stop()
        for collector in collectors:
            collector.join(timeout=5)
        logger.info("Collectors stopped.")
        if database is not None:
            database.close()
            logger.info("Database closed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
