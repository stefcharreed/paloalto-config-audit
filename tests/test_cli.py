"""CLI tests — exit codes are the contract for cron/automation use.

The live collector is monkeypatched at the cli module seam (cli.collect_all),
so these run the real command paths with zero network.
"""
import subprocess
from pathlib import Path

from panos_audit import cli
from panos_audit.collector import CollectionResult

FIXTURES = Path(__file__).parent / "fixtures"
BASELINE = (FIXTURES / "fw1_baseline.xml").read_text(encoding="utf-8")
CLEAN = (FIXTURES / "fw1_current_clean.xml").read_text(encoding="utf-8")
DRIFT = (FIXTURES / "fw1_current_drift.xml").read_text(encoding="utf-8")


def _project(tmp_path, monkeypatch, current_text: str, baseline_text: str | None = BASELINE):
    """Temp project: config.yaml, git-inited backup repo, optional baseline,
    and a monkeypatched collector returning `current_text`."""
    backups = tmp_path / "backups"
    baselines = tmp_path / "baselines"
    backups.mkdir()
    baselines.mkdir()
    subprocess.run(["git", "init", "-q", str(backups)], check=True)
    subprocess.run(
        ["git", "-C", str(backups), "config", "user.email", "t@example.test"], check=True
    )
    subprocess.run(["git", "-C", str(backups), "config", "user.name", "Test"], check=True)

    if baseline_text is not None:
        (baselines / "fw1.xml").write_text(baseline_text, encoding="utf-8")

    config = tmp_path / "config.yaml"
    config.write_text(
        f"settings:\n"
        f"  backup_dir: \"{backups}\"\n"
        f"  baseline_dir: \"{baselines}\"\n"
        f"  report_path: \"{tmp_path / 'reports'}\"\n"
        f"devices:\n"
        f"  - name: fw1\n"
        f"    host: 192.0.2.1\n"
        f"    mode: firewall\n"
    )
    monkeypatch.setenv("PANOS_API_KEY", "test-key")

    def fake_collect_all(devices, source_texts=None):
        return [CollectionResult(device=d.name, ok=True, config_text=current_text)
                for d in devices]

    monkeypatch.setattr(cli, "collect_all", fake_collect_all)
    return config, backups


def test_missing_config_exits_2(tmp_path):
    assert cli.main(["-c", str(tmp_path / "nope.yaml"), "diff"]) == 2


def test_backup_writes_and_commits(tmp_path, monkeypatch):
    config, backups = _project(tmp_path, monkeypatch, CLEAN)
    assert cli.main(["-c", str(config), "backup"]) == 0
    assert (backups / "fw1.xml").read_text(encoding="utf-8") == CLEAN
    log = subprocess.run(
        ["git", "-C", str(backups), "log", "--oneline"],
        capture_output=True, text=True, check=True,
    ).stdout
    assert "Config backup" in log


def test_diff_exit_0_when_in_sync(tmp_path, monkeypatch):
    config, _ = _project(tmp_path, monkeypatch, CLEAN)
    assert cli.main(["-c", str(config), "diff"]) == 0


def test_diff_exit_1_on_drift(tmp_path, monkeypatch):
    config, _ = _project(tmp_path, monkeypatch, DRIFT)
    assert cli.main(["-c", str(config), "diff"]) == 1


def test_report_writes_json(tmp_path, monkeypatch):
    config, _ = _project(tmp_path, monkeypatch, DRIFT)
    assert cli.main(["-c", str(config), "report"]) == 0
    reports = list((tmp_path / "reports").glob("run-*.json"))
    assert len(reports) == 1
    assert '"fw1"' in reports[0].read_text()


def test_failed_collection_exits_nonzero_on_backup(tmp_path, monkeypatch):
    config, _ = _project(tmp_path, monkeypatch, CLEAN)

    def broken_collect_all(devices, source_texts=None):
        return [CollectionResult(device=d.name, ok=False, error="boom") for d in devices]

    monkeypatch.setattr(cli, "collect_all", broken_collect_all)
    assert cli.main(["-c", str(config), "backup"]) == 1
