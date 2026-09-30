"""Configurable passive detection engine."""

from __future__ import annotations

import logging
from typing import Any

from core.events import TelemetryEvent
from detection.base import Detection, Detector
from detection.rules import (
    ProcessStateDetector,
    RepeatedAuth401Detector,
    RequestRateDetector,
    StatusAnomalyDetector,
    UrlSqlInjectionDetector,
)


class DetectionEngine:
    def __init__(self, config: dict[str, Any] | None = None, logger: logging.Logger | None = None) -> None:
        settings = config or {}
        self.enabled = bool(settings.get("enabled", False))
        self.logger = logger or logging.getLogger("edr4")
        cooldown = float(settings.get("cooldown_seconds", 60))
        self.detectors: list[Detector] = []

        sqli = settings.get("url_sqli", {})
        if sqli.get("enabled", True):
            self.detectors.append(UrlSqlInjectionDetector(cooldown_seconds=cooldown))
        rate = settings.get("request_rate", {})
        if rate.get("enabled", True):
            self.detectors.append(RequestRateDetector(
                window_seconds=float(rate.get("window_seconds", 10)),
                threshold=int(rate.get("threshold", 30)),
                per_source_threshold=int(rate.get("per_source_threshold", 20)),
                cooldown_seconds=cooldown,
            ))
        auth = settings.get("auth_401", {})
        if auth.get("enabled", True):
            self.detectors.append(RepeatedAuth401Detector(
                window_seconds=float(auth.get("window_seconds", 60)),
                threshold=int(auth.get("threshold", 5)),
                path_fragments=list(auth.get("path_fragments", ["/login", "/authenticate"])),
                cooldown_seconds=cooldown,
            ))
        status = settings.get("status_anomaly", {})
        if status.get("enabled", True):
            self.detectors.append(StatusAnomalyDetector(
                window_seconds=float(status.get("window_seconds", 60)),
                minimum_requests=int(status.get("minimum_requests", 20)),
                client_error_ratio=float(status.get("client_error_ratio", 0.5)),
                server_error_ratio=float(status.get("server_error_ratio", 0.2)),
                cooldown_seconds=cooldown,
            ))
        process = settings.get("process_state", {})
        if process.get("enabled", True):
            self.detectors.append(ProcessStateDetector(
                abnormal_states=list(process.get(
                    "abnormal_states", ["dead", "zombie", "stopped", "tracing-stop"]
                )),
                cooldown_seconds=cooldown,
            ))

    def process(self, event: TelemetryEvent) -> list[Detection]:
        if not self.enabled or event.event_type == "detection":
            return []
        findings: list[Detection] = []
        for detector in self.detectors:
            try:
                findings.extend(detector.process(event))
            except Exception as exc:
                self.logger.error("[DETECTION] %s failed: %s", type(detector).__name__, exc)
        return findings
