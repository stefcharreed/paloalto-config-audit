# paloalto-config-audit

*Built as part of a NetDevOps portfolio.*

A Python tool that pulls PAN-OS/Panorama configuration over the PAN-OS API, version-controls it in git, and flags configuration drift against a per-device baseline — the same drift-detection pattern as [netmiko-config-audit](https://github.com/stefcharreed/netmiko-config-audit), applied to firewall policy instead of Cisco IOS.

> **Status:** 🚧 Offline pipeline complete — collector, normalize, drift, git backend, and CLI covered by a 46-test suite against sanitized fixtures, with lint + tests in CI (Python 3.10–3.12). **Not yet validated against a real firewall or Panorama instance** — that's the gate before anything here is called "working." See [Roadmap](#roadmap), [THREAT-MODEL.md](THREAT-MODEL.md), and [COMPARISON.md](COMPARISON.md) for the same-bar gap analysis against [netmiko-config-audit](https://github.com/stefcharreed/netmiko-config-audit).

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

1. `cp config/config.example.yaml config/config.yaml` and point `backup_dir`/`baseline_dir` at a **separate, private** git repo — same rule as netmiko-config-audit: real firewall configs are never safe in a public repo.
2. `cp secrets.env.example secrets.env` and set `PANOS_API_KEY`.

### Getting an API key

```
GET https://<firewall-or-panorama>/api/?type=keygen&user=<username>&password=<password>
```

Generate this once, store the returned key in `secrets.env`, and never re-derive it from a stored password at runtime — the key itself is the credential the tool uses going forward.

## Usage

```bash
panos-audit backup     # pull configs and commit them to the backup repo
panos-audit diff       # drift check: current vs. per-device baseline
panos-audit report     # pull, drift-check, and write a JSON run summary
```

Baselines aren't authored by this tool yet (see [Roadmap](#roadmap)) — until `promote`/`set-baseline` land, write a device's first baseline by hand into `baseline_dir/<device>.xml` from a known-good config pull.

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
- [ ] **Validate the collector against a real firewall or Panorama instance** — nothing below this line should be trusted as "working" until this happens (per the "validate against the real thing" rule — fixtures prove logic, real gear proves it works)
- [ ] Human-gated `promote` (approve a drifted config into the baseline) — port from netmiko-config-audit's design
- [ ] `set-baseline` — author a baseline from a file, no live pull needed
- [ ] Rule-level drift summaries (which specific security rule changed, not just a raw XML diff) — likely needs PAN-OS's structured rulebase API endpoints instead of a raw config dump
- [ ] Scheduled nightly run
- [ ] Tie into the existing [network-observability](https://github.com/stefcharreed/network-observability) Prometheus/Grafana stack — surface drift status as a metric

## License

MIT — see [LICENSE](LICENSE).
