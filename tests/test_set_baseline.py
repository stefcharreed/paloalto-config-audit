"""set_baseline.py: pure planning from an arbitrary source file."""
from pathlib import Path

from panos_audit.set_baseline import plan_set_baseline

FIXTURES = Path(__file__).parent / "fixtures"
BASELINE = (FIXTURES / "fw1_baseline.xml").read_text(encoding="utf-8")
DRIFT = (FIXTURES / "fw1_current_drift.xml").read_text(encoding="utf-8")


def test_initial_from_file(tmp_path):
    src = tmp_path / "authored.xml"
    src.write_text(BASELINE, encoding="utf-8")
    baseline_dir = tmp_path / "baselines"
    baseline_dir.mkdir()
    plan = plan_set_baseline("fw1", src, baseline_dir)
    assert plan.is_initial is True
    assert plan.source_text == BASELINE
    assert list(baseline_dir.iterdir()) == []      # plan never writes


def test_matching_file_reports_no_drift(tmp_path):
    src = tmp_path / "authored.xml"
    src.write_text(BASELINE, encoding="utf-8")
    baseline_dir = tmp_path / "baselines"
    baseline_dir.mkdir()
    (baseline_dir / "fw1.xml").write_text(BASELINE, encoding="utf-8")
    plan = plan_set_baseline("fw1", src, baseline_dir)
    assert plan.is_initial is False
    assert plan.has_drift is False


def test_differing_file_shows_the_delta(tmp_path):
    src = tmp_path / "authored.xml"
    src.write_text(DRIFT, encoding="utf-8")
    baseline_dir = tmp_path / "baselines"
    baseline_dir.mkdir()
    (baseline_dir / "fw1.xml").write_text(BASELINE, encoding="utf-8")
    plan = plan_set_baseline("fw1", src, baseline_dir)
    assert plan.has_drift is True
    assert any("temp-emergency-access" in line for line in plan.diff_lines)
