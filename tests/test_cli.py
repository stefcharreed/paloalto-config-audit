"""CLI tests — exit codes and the interactive gates are the contract.

Same testing approach as netmiko-config-audit's test_cli.py:
  - builtins.input is monkeypatched directly (the gates use plain input(), not
    rich Prompts, specifically so this works)
  - cli._interactive is monkeypatched (not sys.stdin) to force either path
  - the live collector is monkeypatched at panos_audit.collector.collect_all
"""
import subprocess
from pathlib import Path

import pytest

from panos_audit import cli, collector
from panos_audit.collector import CollectionResult

FIXTURES = Path(__file__).parent / "fixtures"
BASELINE = (FIXTURES / "fw1_baseline.xml").read_text(encoding="utf-8")
CLEAN = (FIXTURES / "fw1_current_clean.xml").read_text(encoding="utf-8")
DRIFT = (FIXTURES / "fw1_current_drift.xml").read_text(encoding="utf-8")


def _git_init(path: Path):
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "t@example.test"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "Test"], check=True)


def _queue_input(monkeypatch, answers: list[str]):
    """Feed scripted answers to input(); raises if a prompt goes unanswered."""
    answers = list(answers)
    monkeypatch.setattr("builtins.input", lambda *a: answers.pop(0))


def _project(tmp_path, monkeypatch, *, current: str | None = None,
             baseline: str | None = None):
    """Temp project: config.yaml, git-inited backup+baseline dirs, optional
    on-disk backup/baseline, secrets wizard disabled, collector patched."""
    backups = tmp_path / "backups"
    baselines = tmp_path / "baselines"
    backups.mkdir()
    baselines.mkdir()
    _git_init(backups)
    _git_init(baselines)

    if current is not None:
        (backups / "fw1.xml").write_text(current, encoding="utf-8")
    if baseline is not None:
        (baselines / "fw1.xml").write_text(baseline, encoding="utf-8")

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
    monkeypatch.setattr(cli, "_ensure_secrets_file", lambda path: None)

    def fake_collect_all(devices, source_texts=None):
        return [CollectionResult(device=d.name, ok=True, config_text=current or CLEAN)
                for d in devices]

    monkeypatch.setattr(collector, "collect_all", fake_collect_all)
    return config, backups, baselines


# --- first-run behavior -----------------------------------------------------

def test_missing_config_noninteractive_fails_fast(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_interactive", lambda: False)
    with pytest.raises(SystemExit) as exc:
        cli.main(["-c", str(tmp_path / "nope.yaml"), "diff"])
    assert exc.value.code == 1


def test_missing_secrets_noninteractive_fails_fast(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_interactive", lambda: False)
    with pytest.raises(SystemExit) as exc:
        cli._ensure_secrets_file(tmp_path / "secrets.env")
    assert exc.value.code == 1


def test_existing_secrets_noninteractive_proceeds_silently(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_interactive", lambda: False)
    secrets = tmp_path / "secrets.env"
    secrets.write_text("PANOS_API_KEY=existing\n")
    cli._ensure_secrets_file(secrets)          # must not prompt or raise
    assert secrets.read_text() == "PANOS_API_KEY=existing\n"


def test_existing_secrets_interactive_decline_leaves_file(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    _queue_input(monkeypatch, [""])            # default N to "Re-enter?"
    secrets = tmp_path / "secrets.env"
    secrets.write_text("PANOS_API_KEY=existing\n")
    cli._ensure_secrets_file(secrets)
    assert secrets.read_text() == "PANOS_API_KEY=existing\n"


def test_secrets_wizard_writes_confirmed_key(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    answers = ["the-key", "the-key"]           # entry + confirm
    monkeypatch.setattr("getpass.getpass", lambda *a: answers.pop(0))
    secrets = tmp_path / "secrets.env"
    cli._ensure_secrets_file(secrets)
    assert "PANOS_API_KEY=the-key" in secrets.read_text()


def test_secrets_wizard_rejects_dotenv_corrupting_shapes():
    assert cli._invalid_secret_reason("ok-key") is None
    assert cli._invalid_secret_reason("bad #key") is not None
    assert cli._invalid_secret_reason("trailing ") is not None
    assert cli._invalid_secret_reason("multi\nline") is not None


# --- backup ------------------------------------------------------------------

def test_backup_writes_and_commits(tmp_path, monkeypatch):
    config, backups, _ = _project(tmp_path, monkeypatch, current=CLEAN)
    assert cli.main(["-c", str(config), "backup"]) == 0
    log = subprocess.run(
        ["git", "-C", str(backups), "log", "--oneline"],
        capture_output=True, text=True, check=True,
    ).stdout
    assert "Config backup" in log


def test_backup_unknown_device_exits_2(tmp_path, monkeypatch):
    config, _, _ = _project(tmp_path, monkeypatch, current=CLEAN)
    assert cli.main(["-c", str(config), "backup", "no-such-fw"]) == 2


def test_backup_failure_exits_1(tmp_path, monkeypatch):
    config, _, _ = _project(tmp_path, monkeypatch, current=CLEAN)

    def broken(devices, source_texts=None):
        return [CollectionResult(device=d.name, ok=False, error="boom") for d in devices]

    monkeypatch.setattr(collector, "collect_all", broken)
    assert cli.main(["-c", str(config), "backup"]) == 1


# --- diff (file-only) ---------------------------------------------------------

def test_diff_in_sync_exit_0(tmp_path, monkeypatch):
    config, _, _ = _project(tmp_path, monkeypatch, current=CLEAN, baseline=BASELINE)
    assert cli.main(["-c", str(config), "diff"]) == 0


def test_diff_drift_exit_1(tmp_path, monkeypatch):
    config, _, _ = _project(tmp_path, monkeypatch, current=DRIFT, baseline=BASELINE)
    assert cli.main(["-c", str(config), "diff"]) == 1


def test_diff_no_baseline_is_distinct_and_exit_1(tmp_path, monkeypatch, capsys):
    """'No baseline yet' must render as its own status pointing at promote,
    never as DRIFT — the whole-config-as-delta output looks like broken drift
    detection otherwise (confirmed live on netmiko's hardware validation)."""
    config, _, _ = _project(tmp_path, monkeypatch, current=CLEAN, baseline=None)
    assert cli.main(["-c", str(config), "diff"]) == 1
    out = capsys.readouterr().out
    assert "NO BASELINE" in out
    assert "promote" in out
    assert "DRIFT" not in out


def test_diff_needs_no_collector(tmp_path, monkeypatch):
    """diff is file-only: it must never touch the network path."""
    config, _, _ = _project(tmp_path, monkeypatch, current=CLEAN, baseline=BASELINE)

    def explode(*a, **k):
        raise AssertionError("diff called the collector")

    monkeypatch.setattr(collector, "collect_all", explode)
    assert cli.main(["-c", str(config), "diff"]) == 0


# --- audit (file-only) ---------------------------------------------------------

def test_audit_clean_rulebase_exit_0(tmp_path, monkeypatch):
    config, _, _ = _project(tmp_path, monkeypatch, current=CLEAN)
    assert cli.main(["-c", str(config), "audit"]) == 0


def test_audit_permissive_rule_exit_1_and_names_it(tmp_path, monkeypatch, capsys):
    config, _, _ = _project(tmp_path, monkeypatch, current=DRIFT)
    assert cli.main(["-c", str(config), "audit"]) == 1
    out = capsys.readouterr().out
    assert "temp-emergency-access" in out
    assert "overly-permissive-rule" in out


def test_audit_no_backup_is_distinct_and_exit_1(tmp_path, monkeypatch, capsys):
    """No backup on disk != a clean audit — nothing was inspected. Same
    distinction diff draws for NO BASELINE, for the same reason."""
    config, _, _ = _project(tmp_path, monkeypatch)
    assert cli.main(["-c", str(config), "audit"]) == 1
    out = capsys.readouterr().out
    assert "NO BACKUP" in out
    assert "backup" in out


def test_audit_needs_no_collector(tmp_path, monkeypatch):
    """audit is file-only: it must never touch the network path."""
    config, _, _ = _project(tmp_path, monkeypatch, current=CLEAN)

    def explode(*a, **k):
        raise AssertionError("audit called the collector")

    monkeypatch.setattr(collector, "collect_all", explode)
    assert cli.main(["-c", str(config), "audit"]) == 0


# --- promote -------------------------------------------------------------------

def test_promote_without_backup_exits_2(tmp_path, monkeypatch):
    config, _, _ = _project(tmp_path, monkeypatch)
    assert cli.main(["-c", str(config), "promote", "fw1"]) == 2


def test_promote_initial_baseline_on_yes(tmp_path, monkeypatch):
    config, _, baselines = _project(tmp_path, monkeypatch, current=CLEAN)
    _queue_input(monkeypatch, ["y"])
    assert cli.main(["-c", str(config), "promote", "fw1"]) == 0
    assert (baselines / "fw1.xml").read_text(encoding="utf-8") == CLEAN
    log = subprocess.run(
        ["git", "-C", str(baselines), "log", "--oneline"],
        capture_output=True, text=True, check=True,
    ).stdout
    assert "Promote baseline — fw1" in log


def test_promote_declined_leaves_baseline_unchanged(tmp_path, monkeypatch):
    config, _, baselines = _project(
        tmp_path, monkeypatch, current=DRIFT, baseline=BASELINE
    )
    _queue_input(monkeypatch, ["n"])
    assert cli.main(["-c", str(config), "promote", "fw1"]) == 1
    assert (baselines / "fw1.xml").read_text(encoding="utf-8") == BASELINE


def test_promote_in_sync_is_a_noop(tmp_path, monkeypatch):
    config, _, _ = _project(tmp_path, monkeypatch, current=CLEAN, baseline=BASELINE)
    # No input queued: in-sync must return before ever prompting.
    assert cli.main(["-c", str(config), "promote", "fw1"]) == 0


# --- set-baseline ---------------------------------------------------------------

def test_set_baseline_missing_file_exits_2(tmp_path, monkeypatch):
    config, _, _ = _project(tmp_path, monkeypatch)
    assert cli.main(["-c", str(config), "set-baseline", "fw1", str(tmp_path / "no.xml")]) == 2


def test_set_baseline_establishes_from_file(tmp_path, monkeypatch):
    config, _, baselines = _project(tmp_path, monkeypatch)
    src = tmp_path / "authored.xml"
    src.write_text(BASELINE, encoding="utf-8")
    _queue_input(monkeypatch, ["y"])
    assert cli.main(["-c", str(config), "set-baseline", "fw1", str(src)]) == 0
    assert (baselines / "fw1.xml").read_text(encoding="utf-8") == BASELINE


def test_set_baseline_matching_file_is_a_noop(tmp_path, monkeypatch):
    config, _, _ = _project(tmp_path, monkeypatch, baseline=BASELINE)
    src = tmp_path / "authored.xml"
    src.write_text(BASELINE, encoding="utf-8")
    # No input queued: already-matching must return before prompting.
    assert cli.main(["-c", str(config), "set-baseline", "fw1", str(src)]) == 0


def test_set_baseline_declined_overwrite(tmp_path, monkeypatch):
    config, _, baselines = _project(tmp_path, monkeypatch, baseline=BASELINE)
    src = tmp_path / "authored.xml"
    src.write_text(DRIFT, encoding="utf-8")
    _queue_input(monkeypatch, ["n"])
    assert cli.main(["-c", str(config), "set-baseline", "fw1", str(src)]) == 1
    assert (baselines / "fw1.xml").read_text(encoding="utf-8") == BASELINE


# --- report ----------------------------------------------------------------------

def test_report_writes_json_and_does_not_backup(tmp_path, monkeypatch):
    """report pulls + drift-checks + writes JSON — it does NOT write backups
    (that's backup's job); mirrors netmiko's command split."""
    config, backups, _ = _project(tmp_path, monkeypatch, baseline=BASELINE)
    assert cli.main(["-c", str(config), "report"]) == 0
    reports = list((tmp_path / "reports").glob("run-*.json"))
    assert len(reports) == 1
    assert not (backups / "fw1.xml").exists()


def test_report_splits_no_baseline_from_drift(tmp_path, monkeypatch, capsys):
    config, _, _ = _project(tmp_path, monkeypatch)     # no baseline at all
    assert cli.main(["-c", str(config), "report"]) == 0
    out = capsys.readouterr().out
    assert "No baseline yet" in out
    assert "promote" in out


# --- configure ---------------------------------------------------------------------

def test_configure_existing_decline_exits_1(tmp_path, monkeypatch):
    config, _, _ = _project(tmp_path, monkeypatch)
    _queue_input(monkeypatch, ["n"])
    assert cli.main(["-c", str(config), "configure"]) == 1
