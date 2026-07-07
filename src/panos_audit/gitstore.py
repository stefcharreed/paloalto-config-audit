"""Git backend: write configs to the backup repo and commit them.

Same design as netmiko-config-audit's gitstore.py — a separate, private git
repo IS the version history. One file per device (`<device>.xml`), overwritten
every run; `commit_changes()` hard-fails if the target isn't already a git
working tree, since without git every prior version is unrecoverable the
instant the next run overwrites it.
"""
from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path

_GIT_TIMEOUT = 30  # seconds


class GitIdentityError(RuntimeError):
    """`git commit` failed because user.name/user.email aren't configured."""


def write_config(backup_dir: Path, device_name: str, config_text: str) -> Path:
    """Write a device's config to backup_dir/<device>.xml and return the path."""
    backup_dir.mkdir(parents=True, exist_ok=True)
    path = backup_dir / f"{device_name}.xml"
    path.write_text(config_text, encoding="utf-8")
    return path


def is_git_repo(path: Path) -> bool:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
        capture_output=True, text=True, timeout=_GIT_TIMEOUT,
    )
    return result.returncode == 0


def git_repo_root(path: Path) -> Path | None:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, timeout=_GIT_TIMEOUT,
    )
    if result.returncode != 0:
        return None
    return Path(result.stdout.strip()).resolve()


def commit_changes(repo_dir: Path, message: str | None = None) -> bool:
    """Stage all changes and commit. Returns True if a commit was made, False if
    there was nothing to commit. Every git call is scoped to repo_dir via a
    `-- .` pathspec — see netmiko-config-audit's gitstore.py docstring for why
    that scoping is load-bearing when backup_dir/baseline_dir share a repo.
    """
    subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "--is-inside-work-tree"],
        check=True, capture_output=True, text=True, timeout=_GIT_TIMEOUT,
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "add", "-A", "--", "."], check=True, timeout=_GIT_TIMEOUT
    )

    staged = subprocess.run(
        ["git", "-C", str(repo_dir), "diff", "--cached", "--quiet", "--", "."],
        timeout=_GIT_TIMEOUT,
    )
    if staged.returncode == 0:
        return False

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    message = message or f"Config backup — {stamp}"
    try:
        subprocess.run(
            ["git", "-C", str(repo_dir), "commit", "-m", message, "--", "."],
            check=True, capture_output=True, text=True, timeout=_GIT_TIMEOUT,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr or ""
        if "Please tell me who you are" in stderr or "user.email" in stderr:
            raise GitIdentityError(
                f"git commit failed in {repo_dir} — no user.name/user.email "
                f"configured for this repo. Fix with:\n"
                f'  git -C {repo_dir} config user.email "you@example.com"\n'
                f'  git -C {repo_dir} config user.name "Your Name"\n'
                f"(or set both globally: `git config --global user.email ...`)"
            ) from exc
        raise
    return True
