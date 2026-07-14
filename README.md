# paloalto-config-audit

*Built as part of a NetDevOps portfolio.*

A Python tool that pulls PAN-OS/Panorama configuration over the PAN-OS API, version-controls it in git, and flags configuration drift against a per-device baseline — the same drift-detection pattern as [netmiko-config-audit](https://github.com/stefcharreed/netmiko-config-audit), applied to firewall policy instead of Cisco IOS.

> **Status:** 🚧 Offline pipeline complete — collector, normalize, drift, git backend, promote/set-baseline, the configure + first-run wizards, and the CLI covered by a 95-test suite against sanitized fixtures, with lint + tests in CI (Python 3.10–3.12). **Not yet validated against a real firewall or Panorama instance** — that's the gate before anything here is called "working"; [VALIDATION.md](VALIDATION.md) is the step-by-step runbook for that session. See [Roadmap](#roadmap), [THREAT-MODEL.md](THREAT-MODEL.md), and [COMPARISON.md](COMPARISON.md) for the same-bar gap analysis against [netmiko-config-audit](https://github.com/stefcharreed/netmiko-config-audit).

## Overview

Firewall policy drifts the same way router configs do: an emergency rule added at 2 a.m. and never cleaned up, a NAT entry hand-edited outside change control, a rule silently disabled during troubleshooting. This tool gives a firewall fleet its memory back:

- **Knows the intended state** — per-device baseline config (version-controlled), same as a change-controlled security-policy approval
- **Captures the actual state** — scheduled pull of every managed firewall's running config via the PAN-OS XML API (direct, or through Panorama for a device group)
- **Explains the gap** — a normalized diff that flags exactly what drifted, on which device

## How it works

```
inventory (config.yaml) ──> collector (PAN-OS API) ──> gitstore ──> backup repo (git history = actual state over time)
                                      │
                                      └──> drift (normalize both sides) ──> report (JSON)
```

| Module | Responsibility |
| --- | --- |
| `inventory.py` | Load device list + settings; merge the API key from `secrets.env` at runtime |
| `collector.py` | Pull config via the PAN-OS XML API — direct firewall, or through Panorama for a device group |
| `normalize.py` | Parse the config XML, strip volatile noise (e.g. per-object `uuid`), re-serialize with stable formatting |
| `drift.py`     | Diff current vs. per-device baseline, after normalizing **both** sides |
| `audit.py`     | Rulebase security checks — flags risky policy itself (e.g. any/any allow rules), not just drift; see [AUDIT-CHECKS.md](AUDIT-CHECKS.md) |
| `gitstore.py`  | Write configs into the backup repo and commit them |
| `report.py`    | Emit a structured JSON summary of the run |
| `sanitize_check.py` | Lint a config for real IPs, API keys, and password hashes before it's committed |

### On drift detection

Same rule as netmiko-config-audit: drift is computed against each firewall's **own** baseline, and `normalize()` is a pure function applied identically to both sides before diffing. For PAN-OS specifically, `normalize()` strips `uuid` attributes (PAN-OS assigns a new one whenever a rule object is re-created, even if nothing else changed — normalizing it out avoids reporting phantom drift on a rule that's actually still correct) but deliberately **keeps** rule order (security policy is evaluated top-down, so a reorder is real, meaningful drift) and every configured rule value.

## Repo structure

```
paloalto-config-audit/
├── README.md
├── LICENSE
├── .gitignore
├── pyproject.toml
├── secrets.env.example          # copy -> secrets.env (gitignored)
├── config/
│   └── config.example.yaml      # copy -> config/config.yaml
├── scripts/
│   └── pre-commit                # secrets/fixture gate — same pattern as netmiko-config-audit
├── src/panos_audit/
│   ├── __init__.py
│   ├── cli.py                   # `panos-audit backup | diff | report`
│   ├── inventory.py             # config + secrets loader
│   ├── collector.py             # PAN-OS API pull (offline-testable via source_text)
│   ├── normalize.py             # XML-aware normalization (pure, both-sides)
│   ├── drift.py                 # per-device baseline diff
│   ├── audit.py                 # rulebase security checks (see AUDIT-CHECKS.md)
│   ├── gitstore.py              # git backend
│   ├── report.py                # JSON run report
│   └── sanitize_check.py        # pre-commit config linter
└── tests/
    ├── test_smoke.py             # phantom-drift guard + real-drift + offline collector seam
    └── fixtures/                 # sanitized XML samples (RFC 5737 IPs, zero real secrets)
```

## Requirements

- Python 3.10+
- `git` available on PATH
- Network reachability to the target firewall(s)/Panorama over HTTPS
- A PAN-OS/Panorama API key (see [Getting an API key](#getting-an-api-key))

## Installation

```bash
git clone git@github.com:stefcharreed/paloalto-config-audit.git
cd paloalto-config-audit
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
```

## Configuration

1. `config/config.yaml` — two ways to set it up:
   - **Interactive:** run `panos-audit configure` — asks once for your private backup
     repo's root directory, offers to create the recommended `snapshots/`, `baselines/`,
     and `reports/` subdirectories under it, then collects your firewall/Panorama list.
     Validates as it goes: a location inside *this* code repo is rejected (must be a
     separate, private repo), and a location that isn't already a git working tree is
     rejected too — both catch real mistakes before a single API call. Also runs
     automatically the first time any command needs `config.yaml` and it doesn't exist.
   - **Manual:** `cp config/config.example.yaml config/config.yaml` and edit it,
     pointing `backup_dir`/`baseline_dir` at a **separate, private** git repo.
2. The API key in `secrets.env` — two ways:
   - **Interactive (first run):** run `panos-audit backup` or `report` with no
     `secrets.env` present — you're prompted for the key (entered twice, must match;
     shapes python-dotenv would silently corrupt are rejected), and the file is written
     for you. If `secrets.env` already exists you're asked `Re-enter the API key? [y/N]`
     — Enter leaves it alone.
   - **Manual:** `cp secrets.env.example secrets.env` and edit it.

   Either way, `secrets.env` is **gitignored — never commit it.**

All interactive setup detects whether a real terminal is attached before prompting.
Under cron there's no stdin, so: if the files exist, commands run silently; if one is
missing, they fail immediately with one clear line instead of hanging.

### Getting an API key

```
GET https://<firewall-or-panorama>/api/?type=keygen&user=<username>&password=<password>
```

Generate this once, store the returned key in `secrets.env`, and never re-derive it from a stored password at runtime — the key itself is the credential the tool uses going forward.

## Usage

```bash
panos-audit configure   # interactively create/replace config.yaml (see Configuration)
panos-audit backup      # pull configs and commit them to the backup repo
panos-audit backup <DEVICE>          # same, but only this one device
panos-audit diff        # drift check: on-disk backups vs. per-device baseline (file-only)
panos-audit audit       # rulebase security checks against on-disk backups (file-only)
panos-audit promote <DEVICE>         # review a device's drift, then approve it into the baseline
panos-audit set-baseline <DEVICE> <FILE>   # author a baseline from a file, no live pull needed
panos-audit report      # pull, drift-check, and write a JSON run summary
```

The lifecycle matches netmiko-config-audit exactly: `backup` captures actual state,
`diff` reviews it against intended state, `promote` blesses the reviewed backup as the
new baseline. A device with no baseline yet shows as **NO BASELINE** in `diff` — a
distinct status from **DRIFT**, since there's nothing to compare against — with a
pointer to `promote`. `promote` shows the exact diff and waits for an interactive
`y/N` before it writes; there is **no `--yes` flag, by design**. Exit codes: `0`
promoted or already in sync, `1` drift shown but declined, `2` no backup to promote.

`audit` is the security layer on top of the drift pipeline: drift asks "did this
firewall change from its approved state?", audit asks "is the state itself risky?"
A rulebase can be perfectly in sync with its baseline and still contain an any/any
allow rule someone approved during an incident. Like `diff`, it's file-only (audits
the on-disk backups; run `backup` first) and exits `1` when it finds something. The
implemented and planned checks are documented in [AUDIT-CHECKS.md](AUDIT-CHECKS.md).

**Why is there no `push`?** netmiko-config-audit can push a baseline back onto a
Cisco device because IOS config is imperative line replay. PAN-OS is different:
candidate configuration + explicit commit is the native write model, which deserves a
design of its own (candidate load → diff preview → human-gated commit) rather than a
transliteration. Deliberately deferred — see [COMPARISON.md](COMPARISON.md).

## Development / offline testing

Same seam as netmiko-config-audit: `fetch_running_config()` takes an optional `source_text`, so the whole pipeline develops and tests against saved XML with no live firewall or Panorama:

```python
from panos_audit.collector import fetch_running_config
result = fetch_running_config(device, source_text=open("tests/fixtures/fw1.xml").read())
```

```bash
pytest tests/ -q
```

## Security

- **Two repos, by design** — this code repo is public; config backups live in a separate, private repo. Real PAN-OS exports contain admin password hashes, pre-shared keys, and your addressing plan.
- The API key lives in `secrets.env` (gitignored), read at runtime. The repo only ever contains `secrets.env.example` with a dummy value.
- `*.xml` is gitignored so a stray local run can't commit a real config here; sanitized fixtures are the one exception and must pass `sanitize_check.py` first.
- Lab-only shortcut currently in `collector.py`: `verify=False` on the HTTPS call, since firewalls/Panorama commonly run self-signed certs. **Pin the real cert or an internal CA bundle before pointing this at anything beyond a lab** — see the TODO in `collector.py`.

## Roadmap

- [x] Repo scaffold, packaging, config + secrets loader, git backend
- [x] PAN-OS API collector with offline `source_text` seam (API key in the `X-PAN-KEY` header, never the query string)
- [x] XML-aware normalization (strips per-object `uuid`, keeps rule order), loud fallback on unparseable input
- [x] Structured JSON run report
- [x] Pre-commit config sanitizer (`sanitize_check.py`, adapted for PAN-OS phash/API-key shapes)
- [x] 46-test suite: sanitizer (incl. every-committed-fixture-is-clean), normalize (phantom-drift guard, order preservation, loud fallback), drift, inventory validation (incl. XPath-unsafe device_group rejection), gitstore (incl. the pathspec-scoping regression test), collector seam, report, CLI exit codes
- [x] Sanitized PAN-OS-shaped XML fixtures (RFC 5737 IPs, fake names, zero secrets)
- [x] CI: ruff + pytest on Python 3.10–3.12, `permissions: contents: read`, pinned actions
- [x] SECURITY.md + THREAT-MODEL.md (assets, attackers, trust boundaries, dated accepted risks)
- [ ] **Validate the collector against a real firewall or Panorama instance** — nothing below this line should be trusted as "working" until this happens (per the "validate against the real thing" rule — fixtures prove logic, real gear proves it works). Runbook: [VALIDATION.md](VALIDATION.md), including harvesting Panorama/multi-vsys scenario fixtures while connected
- [x] Human-gated `promote` (approve a drifted config into the baseline) — ported from netmiko-config-audit; plan/apply split, y/N gate, exit codes 0/1/2 (offline-tested; not yet run against real gear)
- [x] `set-baseline` — author a baseline from a file, no live pull needed (offline-tested)
- [x] `configure` wizard + first-run API-key setup — repo-root-first flow with separate-repo/git-worktree validation, TTY detection for cron safety, dotenv-corruption-shape rejection (offline-tested)
- [x] `backup <DEVICE>` — single-device backup
- [x] NO BASELINE vs DRIFT distinction in `diff`/`report` (the netmiko lesson: a first-ever diff with no baseline looks like broken drift detection otherwise)
- [x] CLAUDE.md — architecture rules for AI-assisted edits, mirroring the sibling repo
- [ ] `push`-equivalent via PAN-OS candidate-config + commit semantics — **deliberately deferred pending its own design**, not transliterated from IOS line replay
- [x] Rulebase security audit — `panos-audit audit` + the check framework in `audit.py`; first two checks implemented (overly-permissive-rule, logging-disabled), remaining checks specced in [AUDIT-CHECKS.md](AUDIT-CHECKS.md) (offline-tested)
- [ ] Remaining audit checks per [AUDIT-CHECKS.md](AUDIT-CHECKS.md): disabled-rule-hygiene, shadowed-rule, broad-service-object, mgmt-plane-settings (the last gated on a real config export)
- [ ] Rule-level drift summaries (which specific security rule changed, not just a raw XML diff) — likely needs PAN-OS's structured rulebase API endpoints instead of a raw config dump
- [ ] Scheduled nightly run
- [ ] Tie into the existing [network-observability](https://github.com/stefcharreed/network-observability) Prometheus/Grafana stack — surface drift status as a metric

## License

MIT — see [LICENSE](LICENSE).
