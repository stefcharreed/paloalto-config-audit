# CLAUDE.md — paloalto-config-audit

PAN-OS/Panorama config drift auditor — the netmiko-config-audit architecture
applied to firewall policy. **Public portfolio repo** — keep it honest, clean,
and free of planning/strategy (that lives in private repos). Its sibling's
CLAUDE.md governs the shared patterns; this file records what's specific here
and which shared rules are load-bearing.

## Commands
- Install: `pip install -e ".[dev]"`
- Test: `pytest tests/ -q` — expect **all passing**; the suite needs no network,
  no live firewall, no API key.
- Lint: `ruff check src/ tests/` (config in `pyproject.toml`) — enforced in CI.
- CLI: `panos-audit backup [DEVICE] | diff | audit | promote <DEVICE> |
  set-baseline <DEVICE> <FILE> | report | configure`

## Layout
- `src/panos_audit/` — inventory, collector, normalize, drift, audit, gitstore,
  promote, set_baseline, report, sanitize_check, cli.
- `tests/` — pytest; sanitized XML fixtures in `tests/fixtures/` (every one
  must pass `python -m panos_audit.sanitize_check` — CI enforces this via
  `test_every_committed_fixture_is_clean`).

## Architecture rules (these govern how you edit — don't break them)
- **Seam discipline:** functions return plain JSON-serializable data and
  **never print**. Rendering (rich tables/panels/colored diffs) lives only in
  `cli.py`'s `_cmd_*` functions.
- **normalize() applies to BOTH sides** (baseline and current) before diffing —
  normalizing one side manufactures phantom drift. It strips per-object `uuid`
  attributes and **never sorts** — security policy is evaluated top-down, so
  rule order is meaningful drift. Its ParseError fallback emits a UserWarning
  on purpose (a silent fallback would mask a broken collector as clean
  text-diffing); empty input is the known no-baseline-yet state and doesn't warn.
- **Per-device baselines.** Drift = "did this firewall change from its own
  last-approved config," never "does it match a fleet template."
- **promote/set-baseline are human-gated with plain `input()`, not rich
  Prompts** — tests monkeypatch `builtins.input` directly. No `--yes` flag, no
  auto-approve path. Do not add one.
- **"No baseline yet" is not "drift."** `compare_to_baseline` can't tell the
  difference (empty baseline vs. real config is always has_drift=True with the
  whole file as delta). `_cmd_diff`/`_cmd_report` check baseline-file existence
  themselves and render `NO BASELINE` (cyan) distinctly from `DRIFT` (yellow),
  pointing at `promote`. Don't collapse them, and don't "fix" it in drift.py —
  that logic is correct. `RunReport.drifted` (the JSON schema) intentionally
  still includes no-baseline devices; only the console rendering splits them.
- **`diff` is file-only** (on-disk backups vs. baselines) — no live pull, no
  credentials. The lifecycle is `backup → diff → promote`; promote operates on
  the ON-DISK backup you reviewed, never a fresh pull (no TOCTOU gap).
- **`audit` is file-only and check-registry-driven** (AUDIT-CHECKS.md is the
  spec; `check_overly_permissive` is the worked example every new check
  follows). Check slugs are stable once shipped — reports key off them. An
  any/any **deny** never fires the permissive check (it's the normal cleanup
  rule), disabled rules never fire it (they pass no traffic), and an
  unparseable config is a high-severity finding, never "clean" — don't relax
  any of those. In logging-disabled, absent `<log-end>` defaults to YES and
  must never fire (PAN-OS omits defaulted elements), and its text comparison
  strips whitespace (pretty-printed exports render `\n  no\n`; exact equality
  would false-negative) — both are pinned by tests. shadowed-rule is
  **name-level only in v1** (no address-object resolution — under-reports,
  never invents) and disabled rules neither shadow nor get flagged there;
  disabled-rule-hygiene owns disabled rules outright, which is WHY every
  other check skips them. NO BACKUP renders distinctly from clean, same reasoning as
  diff's NO BASELINE.
- **`report` does not write backups** — it pulls, drift-checks, and writes the
  JSON summary. Backups are `backup`'s job.
- **Every interactive wizard checks `_interactive()` first** (load-bearing,
  inherited from a real netmiko cron breakage): missing file + non-interactive →
  one clear line + `SystemExit(1)`; existing file + non-interactive → proceed
  silently, never prompt. The secrets wizard only fires for `backup`/`report`
  (the commands that touch live gear). Tests monkeypatch `cli._interactive`,
  not `sys.stdin`.
- **`_invalid_secret_reason()` rejects API-key shapes python-dotenv silently
  corrupts** (' #' truncation, trailing whitespace, newlines) — verified
  behavior in the netmiko sibling, same dotenv.
- **The configure wizard asks for one repo root**, then offers
  `snapshots/`/`baselines/`/`reports/` under it — never three independently
  typed paths (that design caused a real path-typo failure in the sibling).
  The root is validated: must NOT resolve inside this code repo, must already
  be a git working tree. Subdirectories inherit the root's validity.
- **`gitstore.commit_changes()` scopes every git call with a `-- .` pathspec** —
  backup_dir and baseline_dir commonly share one private repo, and without the
  pathspec a `backup` run sweeps in pending baseline edits, corrupting the
  "who approved what, when" audit trail. Regression test in `test_gitstore.py`.
- **git history is the timeline.** One `<device>.xml` per device, overwritten
  each run; `git log <device>.xml` is the change log. No timestamped filenames.
  Never manually copy a file into baseline_dir/backup_dir — always go through
  `promote`/`set-baseline`/`backup` (manual copies skip the commit and the gate).
- **There is deliberately no `push` command.** PAN-OS has candidate-config +
  commit semantics — a fundamentally different write model than IOS line replay.
  A push-equivalent needs its own design (candidate load + diff preview +
  human-gated commit, probably via the API's config actions), decided
  deliberately — do not transliterate netmiko's push. See COMPARISON.md.
- **The API key goes in the `X-PAN-KEY` header, never a `key=` query param** —
  query strings land in web-server/proxy access logs.
- **`device_group` is validated at inventory load** against `[A-Za-z0-9._ -]` —
  it's spliced into an XPath; a quote in the name must be a config error, not a
  malformed API query.

## Safety / risk zones
- **Never commit secrets.** The API key lives in `secrets.env` (gitignored),
  read at runtime. `config.yaml` holds addressing only and is also gitignored.
- **Fixtures must be publish-safe:** RFC 5737 doc IPs, fake names, zero real
  hashes/keys. Run `python -m panos_audit.sanitize_check <file>` before any
  `.xml` enters `tests/fixtures/`.
- **Real configs/baselines live in a separate private repo**, never here — a
  PAN-OS config is the security policy itself, a literal attack map.
- **NOTHING here is hardware-validated yet.** The collector's live path
  (X-PAN-KEY, xpath shapes, response envelope) has never touched a real
  firewall or Panorama. Fixtures prove logic; real gear proves it works. Do not
  describe any live path as validated/working until it has actually run against
  real PAN-OS — see README's roadmap gate and THREAT-MODEL.md AR-1
  (`verify=False` is lab-only).

## Before saying "done"
1. `pytest tests/ -q` green.
2. `ruff check src/ tests/` clean.
3. `git status` — confirm no `secrets.env`, real IPs, or keys staged (the
   pre-commit hook backstops this; install it: `ln -sf ../../scripts/pre-commit
   .git/hooks/pre-commit`).
