"""Author a device's baseline directly from a config file, with no live pull
first. Direct port of netmiko-config-audit's set_baseline.py.

promote.py's lifecycle (backup -> diff -> promote) assumes a live device already
exists to pull FROM. Pre-staging is the opposite: the desired config is authored
ahead of time (hand-written, exported from a lab firewall, or a device-group
template) — there is no live state to promote from yet. This module is that
authoring step: it reads an arbitrary file (not backup_dir) and produces a plan
the CLI can show a human before writing.

plan_set_baseline() is pure — no writes. The actual write reuses
promote.apply_promotion() (same operation: write raw text to
baseline_dir/<device>.xml) rather than duplicating it — the two commands differ
only in where the text comes from, not in how it gets written.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .drift import compare_to_baseline


@dataclass
class SetBaselinePlan:
    device: str
    baseline_exists: bool       # did a baseline already exist before this?
    is_initial: bool            # True == establishing the very first baseline
    has_drift: bool             # does the source file differ from the existing baseline?
    diff_lines: list[str]       # unified-diff lines to show the human (empty if in sync)
    source_text: str            # the RAW source file text that would become the baseline


def plan_set_baseline(device_name: str, source_path: Path, baseline_dir: Path) -> SetBaselinePlan:
    """Analyze setting a baseline from an arbitrary file. No writes, no prompts.

    source_path is any config file/template — not backup_dir. Diffed against the
    current baseline (if any) via the same normalize()-based comparison drift.py
    and promote.py already use, so the review a human sees here is consistent
    with `diff`/`promote`.
    """
    source_text = Path(source_path).read_text(encoding="utf-8")
    baseline_path = Path(baseline_dir) / f"{device_name}.xml"

    if not baseline_path.exists():
        result = compare_to_baseline(device_name, source_text, "")
        return SetBaselinePlan(
            device=device_name, baseline_exists=False, is_initial=True,
            has_drift=result.has_drift, diff_lines=result.diff_lines,
            source_text=source_text,
        )

    baseline_text = baseline_path.read_text(encoding="utf-8")
    result = compare_to_baseline(device_name, source_text, baseline_text)
    return SetBaselinePlan(
        device=device_name, baseline_exists=True, is_initial=False,
        has_drift=result.has_drift, diff_lines=result.diff_lines,
        source_text=source_text,
    )
