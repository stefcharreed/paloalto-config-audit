"""promote.py: plan is pure analysis across all four states and never writes;
apply is the single write and round-trips exactly. Mirrors netmiko's suite."""
from pathlib import Path

from panos_audit.promote import apply_promotion, plan_promotion

FIXTURES = Path(__file__).parent / "fixtures"
BASELINE = (FIXTURES / "fw1_baseline.xml").read_text(encoding="utf-8")
CLEAN = (FIXTURES / "fw1_current_clean.xml").read_text(encoding="utf-8")
DRIFT = (FIXTURES / "fw1_current_drift.xml").read_text(encoding="utf-8")


def _dirs(tmp_path):
    backup = tmp_path / "backups"
    baseline = tmp_path / "baselines"
    backup.mkdir()
    baseline.mkdir()
    return backup, baseline


def test_no_backup_state(tmp_path):
    backup, baseline = _dirs(tmp_path)
    plan = plan_promotion("fw1", backup, baseline)
    assert plan.backup_exists is False
    assert plan.is_initial is False
    assert plan.current_text == ""


def test_initial_baseline_state(tmp_path):
    backup, baseline = _dirs(tmp_path)
    (backup / "fw1.xml").write_text(BASELINE, encoding="utf-8")
    plan = plan_promotion("fw1", backup, baseline)
    assert plan.backup_exists is True
    assert plan.baseline_exists is False
    assert plan.is_initial is True
    assert plan.has_drift is True          # whole config is the delta
    assert plan.current_text == BASELINE


def test_in_sync_state(tmp_path):
    backup, baseline = _dirs(tmp_path)
    (backup / "fw1.xml").write_text(CLEAN, encoding="utf-8")     # uuid/format noise only
    (baseline / "fw1.xml").write_text(BASELINE, encoding="utf-8")
    plan = plan_promotion("fw1", backup, baseline)
    assert plan.is_initial is False
    assert plan.has_drift is False
    assert plan.diff_lines == []


def test_drifted_state(tmp_path):
    backup, baseline = _dirs(tmp_path)
    (backup / "fw1.xml").write_text(DRIFT, encoding="utf-8")
    (baseline / "fw1.xml").write_text(BASELINE, encoding="utf-8")
    plan = plan_promotion("fw1", backup, baseline)
    assert plan.has_drift is True
    assert any("temp-emergency-access" in line for line in plan.diff_lines)


def test_plan_never_writes(tmp_path):
    backup, baseline = _dirs(tmp_path)
    (backup / "fw1.xml").write_text(DRIFT, encoding="utf-8")
    plan_promotion("fw1", backup, baseline)
    assert list(baseline.iterdir()) == []


def test_apply_round_trips_raw_text(tmp_path):
    _, baseline = _dirs(tmp_path)
    path = apply_promotion("fw1", DRIFT, baseline)
    assert path.read_text(encoding="utf-8") == DRIFT
