"""Run-report tests — the JSON seam downstream tooling will read."""
import json

from panos_audit.collector import CollectionResult
from panos_audit.drift import DriftResult
from panos_audit.report import build_report, write_report


def test_report_counts_and_names():
    results = [
        CollectionResult(device="fw1", ok=True, config_text="<a/>"),
        CollectionResult(device="fw2", ok=False, error="connection refused"),
    ]
    drift = [DriftResult(device="fw1", has_drift=True, diff_lines=["+x"])]
    report = build_report(results, drift)
    assert report.devices_total == 2
    assert report.devices_ok == 1
    assert report.devices_failed == 1
    assert report.drifted == ["fw1"]
    assert report.failures == {"fw2": "connection refused"}


def test_written_filename_matches_internal_timestamp(tmp_path):
    report = build_report([], [])
    path = write_report(report, tmp_path)
    assert path.name == f"run-{report.timestamp}.json"
    data = json.loads(path.read_text())
    assert data["timestamp"] == report.timestamp
