"""Structured reporting: emit a JSON summary of a run.

Same seam as netmiko-config-audit's report.py — JSON output so a later
correlation layer (or the existing network-observability Grafana stack) can
read run history without depending on this tool's internals.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class RunReport:
    timestamp: str
    devices_total: int = 0
    devices_ok: int = 0
    devices_failed: int = 0
    drifted: list[str] = field(default_factory=list)
    failures: dict = field(default_factory=dict)


def build_report(results, drift_results) -> RunReport:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report = RunReport(timestamp=stamp)

    report.devices_total = len(results)
    report.devices_ok = sum(1 for r in results if r.ok)
    report.devices_failed = sum(1 for r in results if not r.ok)
    report.drifted = [d.device for d in drift_results if d.has_drift]
    report.failures = {r.device: r.error for r in results if not r.ok}
    return report


def write_report(report: RunReport, report_dir: Path) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"run-{report.timestamp}.json"
    path.write_text(json.dumps(asdict(report), indent=2))
    return path
