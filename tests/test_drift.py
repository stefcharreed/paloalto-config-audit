"""Drift detection against the committed fixtures."""
from pathlib import Path

from panos_audit.drift import compare_to_baseline, load_baseline

FIXTURES = Path(__file__).parent / "fixtures"
BASELINE = (FIXTURES / "fw1_baseline.xml").read_text(encoding="utf-8")


def _added(result) -> str:
    return "\n".join(
        d for d in result.diff_lines if d.startswith("+") and not d.startswith("+++")
    )


def test_no_drift_when_only_noise_differs():
    current = (FIXTURES / "fw1_current_clean.xml").read_text(encoding="utf-8")
    result = compare_to_baseline("fw1", current, BASELINE)
    assert result.has_drift is False
    assert result.diff_lines == []


def test_real_policy_drift_detected():
    """The 2 a.m. scenario the README describes: a service narrowed to `any`
    and an emergency allow-any rule left behind — both must surface."""
    current = (FIXTURES / "fw1_current_drift.xml").read_text(encoding="utf-8")
    result = compare_to_baseline("fw1", current, BASELINE)
    assert result.has_drift is True
    added = _added(result)
    assert "temp-emergency-access" in added
    assert "any" in added


def test_missing_baseline_reads_as_empty(tmp_path):
    assert load_baseline(tmp_path, "no-such-device") == ""


def test_empty_baseline_vs_real_config_is_drift():
    result = compare_to_baseline("fw1", BASELINE, "")
    assert result.has_drift is True
