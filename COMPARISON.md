# paloalto-config-audit vs. netmiko-config-audit — gap analysis

Written 2026-07-07, the day this repo was scaffolded. Both projects are held to
the same bar; findings run in **both** directions. Items marked ⬜ are open work
in this repo; items marked ⚠️ are findings against netmiko-config-audit found
during this comparison.

**Baseline for comparison:** netmiko-config-audit v1.1 — feature-complete,
hardware-validated, 137 tests, CI + Docker + Trivy. This repo is a day-old
scaffold. The point of this document is that "scaffold" is not an excuse to
hold it to a lower standard — it's a dated, explicit list of exactly what the
standard requires before this repo can claim parity.

---

## Architecture

### At parity (deliberately identical design)

| Property | Both repos |
|---|---|
| Module decomposition | `inventory → collector → gitstore` / `collector → normalize → drift → report`, one responsibility each |
| Seam discipline | Every function under `src/` returns plain JSON-serializable data and never prints; rendering lives only in `cli.py` |
| Offline test seam | `fetch_running_config(device, source_text=...)` — whole pipeline develops/tests against saved configs, no live gear |
| Both-sides normalization | `normalize()` is pure and applied identically to baseline and current; the phantom-drift guard test enforces it |
| Git-backed history | One file per device, overwritten per run; git history IS the timeline; `commit_changes()` hard-fails outside a git repo; every git call scoped with a `-- .` pathspec |
| Two-repo model | Public code repo / private backup repo, enforced by `.gitignore` + docs |
| Lazy transport import | `netmiko` / `requests` imported inside the live path only, so the offline path imports clean |
| Per-device failure isolation | One unreachable device becomes `ok=False` data in the report, never a crashed run |

### Platform-appropriate differences (not gaps)

| | netmiko-config-audit | paloalto-config-audit |
|---|---|---|
| Transport | SSH (Netmiko) | HTTPS (PAN-OS XML API), direct or via Panorama device-group |
| Config shape | Line-based IOS text | XML — `normalize()` parses and re-serializes instead of stripping line prefixes |
| Volatile noise stripped | `show run` header, `ntp clock-period` | Per-object `uuid` attributes |
| Order preservation | ACL/line order kept (meaningful) | Rule order kept (security policy is top-down — a reorder is real drift) |
| Credentials | username/password/enable via `secrets.env` | Single API key via `secrets.env` |

### ⬜ Architecture gaps in this repo (all on the README roadmap)

1. **No `promote`** — the human-gated approve-drift-into-baseline flow. In
   netmiko this is the heart of the audit trail ("who blessed which config as
   intended, when"). Until it's ported, baselines here are hand-authored files
   with no gate.
2. **No `push` / `set-baseline`** — remediation and ZTP flows. Note `push` may
   not port cleanly: PAN-OS has candidate-config + commit semantics, which is a
   fundamentally different (and safer) model than IOS's imperative line replay.
   Decide the design before porting, don't transliterate.
3. **No `configure` wizard / interactive secrets setup** — netmiko validates the
   backup-repo path (separate repo, is-a-git-worktree) *before* any device is
   contacted. Here, misconfiguration surfaces as a runtime failure.
4. **No single-device `backup <DEVICE>`.**
5. **No MCP adapter.**
6. **Doc/behavior mismatch in `normalize.py`** (this repo): the docstring says
   the ParseError fallback is "deliberately loud," but the code falls back
   silently — nothing signals the caller. Either emit a warning into the result
   path or fix the docstring. A silent fallback on malformed API output can
   mask a broken collector as clean text-diffing.
7. **Unescaped string interpolation in `_xpath_for()`**: `device_group` is
   spliced into the XPath inside single quotes. Operator-controlled input, so
   low severity, but a name containing `'` produces a malformed query. Netmiko
   has no equivalent string-built query surface.

---

## Security

### At parity

- `.gitignore`-first secrets posture: `*.env` blocked, only `*.example`
  committable; real configs (`*.cfg` / `*.xml`) blocked with fixtures re-included.
- `secrets.env` read at runtime, never in the repo.
- `scripts/pre-commit` gate (blocks real env files, runs the sanitizer on staged
  configs, hard secret patterns, opportunistic gitleaks). Adapted here for
  PAN-OS shapes: phash elements, password elements, LUFRPT-prefixed API keys.
  (Named without their literal XML/token syntax on purpose — the gate correctly
  blocked the first draft of this document for containing the exact byte
  patterns it scans for.)
- Sanitizer as a pure function (`check_config`) with the same RFC 5737-only IP
  policy, wildcard-mask and 0.0.0.0/8 handling.

### Security work done in this repo that netmiko didn't need

- **API key in `X-PAN-KEY` header, not the query string** (fixed 2026-07-07,
  same day it was found in review): a `key=` query parameter is written to
  web-server/proxy access logs — an API key in a log line is a leaked
  credential. SSH credentials never had this failure mode.

### ⬜ Security gaps in this repo

1. **No CI at all** — netmiko has `permissions: contents: read`, pinned action
   versions, a 3.10–3.12 test matrix, a Docker test stage, and a calibrated
   Trivy scan (`--ignore-unfixed`, HIGH/CRITICAL). Per the global standard
   ("CI is least-privilege *from the start*"), CI belongs in this repo before
   the first push, not after.
2. **No SECURITY.md** — netmiko's defines private vulnerability reporting and
   scope in 16 lines. Straight port.
3. **No threat-model note** — the global standard requires a short written
   threat model (assets, who'd attack, trust boundaries) *before first push*.
   Not yet violated (repo hasn't been pushed) but it gates the push.
4. **`verify=False` on the HTTPS call** is currently a code TODO. The standard
   says accepted risks are *dated decisions*, not TODOs. Decision, recorded
   here (2026-07-07): acceptable **only while the tool points at a lab
   firewall**; pinning a real cert / internal CA bundle is a blocker for any
   production use. This also means `urllib3` will emit InsecureRequestWarning
   noise on every call — treat that warning as the reminder, don't suppress it.
5. **Sanitizer has no SNMP check** — PAN-OS configs carry
   `<snmp-setting>`/community strings too; netmiko's sanitizer flags
   `snmp-server community`, this one flags nothing SNMP-shaped. Port the check
   against a real PAN-OS export's actual XML shape (don't guess the element
   names — see the "validate against the real thing" rule).
6. **Process finding (this scaffold's own history):** the initial commit was
   made *before* the pre-commit hook symlink was installed — the gate the
   global standard requires "on every clone" wasn't active for commit one.
   Content was verified clean after the fact, but the standard exists precisely
   so that verification isn't retroactive. Hook installed 2026-07-07, active
   for every commit after the first.

### ⚠️ Findings against netmiko-config-audit

- **Ruff is configured but not enforced and currently failing**: pyproject.toml
  carries a full `[tool.ruff.lint]` config, but `ruff check src/ tests/` fails
  with **27 errors** as of 2026-07-07, and CI runs pytest + Docker only — no
  lint step. Either fix the 27 and add ruff to CI, or delete the config; a
  lint config that isn't run is documentation that lies. (This repo passes
  ruff clean as of the same date, checked with the same config.)

---

## Tests

### The gap, in numbers (2026-07-07)

| | netmiko-config-audit | paloalto-config-audit |
|---|---|---|
| Test count | **137** (109 tool + 28 MCP) across 16 files | **3** in 1 file |
| CLI tests | 44 | 0 |
| gitstore tests | 9 | 0 |
| sanitizer tests | 11 | **0** — notable: the pre-commit gate depends on an untested sanitizer |
| inventory/validation tests | 5 | 0 |
| report tests | 3 | 0 |
| Fixtures | `tests/fixtures/` with sanitized `.cfg` files, each required to pass the sanitizer | **None** — inline strings only; the fixtures dir is empty and (being empty) isn't even tracked by git |
| Python versions proven | 3.10 / 3.11 / 3.12 in CI | 3.14 locally, once — `requires-python >=3.10` has never been verified on 3.10 |
| Validated against real gear | ✅ full pipeline on a physical switch | ❌ never touched a firewall or Panorama |

### What the 3 tests here do prove

The three smoke tests are the *right* three to start with — they're the
load-bearing properties, in the same priority order netmiko's suite treats them:

1. **Phantom-drift guard** — uuid + whitespace differences normalize away.
2. **Real drift detected** — an action flip (`allow`→`deny`) is caught.
3. **Offline collector seam** — `source_text` bypasses the network.

### ⬜ Test debt, in the order it should be paid

1. Sanitizer tests (the pre-commit gate is only as good as its untested regexes
   — netmiko's 11 sanitizer tests include the wildcard-mask false-positive
   cases that were actually hit).
2. Committed, sanitizer-passing XML fixtures (a real-shaped PAN-OS export,
   sanitized — inline strings can't represent the size/nesting of real output).
3. Inventory validation tests (missing fields, bad `mode`, panorama-without-
   device_group — the error paths exist, nothing proves them).
4. gitstore tests (pathspec scoping has a regression test in netmiko because it
   caught a real bug; the same code was copied here, so the same test should
   guard it).
5. CLI tests (netmiko's largest file at 44 — exit codes are the contract for
   cron/automation use).
6. CI running all of it on 3.10–3.12 (+ ruff, which netmiko should also add).

### Real-gear validation status (same bar, stated the same way)

netmiko-config-audit's README could only claim ✅ after live SSH pull, promote,
induced drift, and push were run against a physical switch. This repo's
equivalent gate: live API pull from an actual firewall or Panorama (lab is
fine), a hand-authored baseline, an induced policy change detected as drift,
and a clean diff after re-baselining. **Until then, nothing here is "working" —
it is "logic proven against fixtures."**

---

## Verdict

Architecture parity is real — the seams, the git-backed audit trail, and the
normalization discipline transferred intact, and one security property
(API-key-in-header) exceeds what the SSH tool needed. Security *process*
parity and test parity do not exist yet: no CI, no SECURITY.md, no threat
model, 3 tests vs 137, zero fixtures, never run against real gear. That's the
expected state for a day-old scaffold, but it's now a dated, enumerated debt
list rather than an implicit one. The one finding flowing the other way —
netmiko's configured-but-failing ruff — gets fixed in that repo, not waived
here.
