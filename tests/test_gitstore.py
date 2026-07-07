"""Git backend tests — including the pathspec-scoping regression test that
exists because the equivalent code in netmiko-config-audit caught a real bug:
without `-- .`, git operates on the whole containing repo, not the subdir."""
import subprocess

import pytest

from panos_audit.gitstore import commit_changes, is_git_repo, write_config


def _git_repo(path):
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "t@example.test"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "Test"], check=True)
    return path


def test_write_config_creates_file(tmp_path):
    path = write_config(tmp_path / "backups", "fw1", "<config/>")
    assert path.name == "fw1.xml"
    assert path.read_text() == "<config/>"


def test_is_git_repo_distinguishes_repo_from_plain_dir(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    plain = tmp_path / "plain"
    plain.mkdir()
    assert is_git_repo(repo) is True
    # GIT_CEILING can't help here: tmp_path itself may sit under a repo on a
    # dev machine, so test a dir we know has no .git between it and tmp_path,
    # after confirming tmp_path itself isn't inside one.
    if not is_git_repo(tmp_path):
        assert is_git_repo(plain) is False


def test_commit_in_fresh_repo(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    write_config(repo, "fw1", "<config/>")
    assert commit_changes(repo) is True


def test_nothing_to_commit_returns_false(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    write_config(repo, "fw1", "<config/>")
    commit_changes(repo)
    assert commit_changes(repo) is False


def test_non_repo_raises(tmp_path):
    write_config(tmp_path / "loose", "fw1", "<config/>")
    with pytest.raises(subprocess.CalledProcessError):
        commit_changes(tmp_path / "loose")


def test_pathspec_scoping_does_not_sweep_sibling_dirs(tmp_path):
    """backup/ and baselines/ commonly share one private repo. A backup commit
    must never sweep in pending baseline edits — that would corrupt the
    'who approved what, when' audit trail."""
    repo = _git_repo(tmp_path / "shared")
    backups = repo / "snapshots"
    baselines = repo / "baselines"
    backups.mkdir()
    baselines.mkdir()

    write_config(backups, "fw1", "<config n='1'/>")
    write_config(baselines, "fw1", "<baseline pending='edit'/>")

    assert commit_changes(backups, "backup only") is True

    # The baseline file must still be uncommitted.
    status = subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain", "-uall"],
        capture_output=True, text=True, check=True,
    ).stdout
    assert "baselines/fw1.xml" in status, "baseline edit was swept into the backup commit"
