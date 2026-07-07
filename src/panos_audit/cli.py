"""CLI: panos-audit backup | diff | report

v1 scope, deliberately smaller than netmiko-config-audit's CLI: backup/diff/report
only. promote/push equivalents (human-gated baseline approval, pushing a baseline
back onto a firewall) are roadmap items — see README — not stubbed here, so
nothing pretends to gate a write it doesn't actually perform.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .collector import collect_all
from .drift import compare_to_baseline, load_baseline
from .gitstore import commit_changes, write_config
from .inventory import load_config
from .report import build_report, write_report

console = Console()


def _cmd_backup(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    results = collect_all(cfg.devices)

    table = Table(title="panos-audit backup")
    table.add_column("device")
    table.add_column("status")
    for r in results:
        if r.ok:
            write_config(cfg.settings.backup_dir, r.device, r.config_text)
            table.add_row(r.device, "[green]ok[/green]")
        else:
            table.add_row(r.device, f"[red]failed: {r.error}[/red]")
    console.print(table)

    committed = commit_changes(cfg.settings.backup_dir)
    console.print("committed to backup repo" if committed else "no changes to commit")
    return 0 if all(r.ok for r in results) else 1


def _cmd_diff(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    results = collect_all(cfg.devices)

    any_drift = False
    for r in results:
        if not r.ok:
            console.print(f"[red]{r.device}: collection failed — {r.error}[/red]")
            continue
        baseline = load_baseline(cfg.settings.baseline_dir, r.device)
        drift = compare_to_baseline(r.device, r.config_text, baseline)
        if drift.has_drift:
            any_drift = True
            console.print(f"[yellow]{r.device}: DRIFT[/yellow]")
            for line in drift.diff_lines:
                color = "green" if line.startswith("+") else "red" if line.startswith("-") else "dim"
                console.print(f"[{color}]{line}[/{color}]")
        else:
            console.print(f"[green]{r.device}: in sync[/green]")
    return 1 if any_drift else 0


def _cmd_report(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    results = collect_all(cfg.devices)
    drift_results = [
        compare_to_baseline(r.device, r.config_text, load_baseline(cfg.settings.baseline_dir, r.device))
        for r in results if r.ok
    ]
    for r in results:
        if r.ok:
            write_config(cfg.settings.backup_dir, r.device, r.config_text)
    commit_changes(cfg.settings.backup_dir)

    report = build_report(results, drift_results)
    path = write_report(report, cfg.settings.report_path)
    console.print(f"wrote report: {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="panos-audit")
    parser.add_argument("-c", "--config", default="config/config.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("backup", help="pull configs and commit them to the backup repo") \
        .set_defaults(func=_cmd_backup)
    sub.add_parser("diff", help="drift check: current vs. per-device baseline") \
        .set_defaults(func=_cmd_diff)
    sub.add_parser("report", help="pull, drift-check, and write a JSON run summary") \
        .set_defaults(func=_cmd_report)

    args = parser.parse_args(argv)
    if not Path(args.config).exists():
        console.print(f"[red]config not found: {args.config}[/red] "
                       f"(cp config/config.example.yaml config/config.yaml)")
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
