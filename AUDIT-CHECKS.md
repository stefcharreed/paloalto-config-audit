# AUDIT-CHECKS.md — rulebase audit checks: implemented + planned

`panos-audit audit` runs the checks registered in `src/panos_audit/audit.py`
against on-disk backups. Drift detection answers "did this firewall change from
its approved state?"; the audit answers the complementary question: "is the
state itself risky?" A rulebase can be perfectly in sync with its baseline and
still contain an any/any allow rule someone approved at 2 a.m.

## How to add a check (the pattern)

`check_overly_permissive()` in `audit.py` is the worked example — every new
check follows its shape:

1. Write a function `(device_name, rules) -> list[Finding]` in `audit.py`.
   It inspects data and returns findings; it never prints, never reads files.
2. Give it a stable kebab-case `check` slug — reports and future tooling key
   off it, so it never changes once shipped.
3. Append the function to the `CHECKS` registry. Nothing else changes —
   `audit_config()` and the CLI pick it up automatically.
4. Tests in `tests/test_audit.py`: a true-positive, a true-negative (the case
   that *looks* like the finding but isn't — this is what keeps the audit
   quiet enough to trust), and any state-handling edge (disabled, missing
   fields). Inline `ET.fromstring` rule snippets are fine; new committed
   fixtures must pass `python -m panos_audit.sanitize_check` first.

Severity vocabulary: `high` (exploitable/exposing as-is), `medium` (weakens
the policy, needs judgment), `low` (hygiene).

## Implemented

### overly-permissive-rule
Enabled `allow` rule with source AND destination both `any`. Severity `high`
when service and application are also `any` (passes literally everything),
`medium` otherwise. Any/any **deny** never fires — that's the normal cleanup
rule. Disabled rules never fire — they pass no traffic (their hygiene is
`disabled-rule-hygiene`, below).

## Planned — build these next, in this order

### 1. logging-disabled  (severity: medium) — SCAFFOLDED
An allow rule with `<log-end>no</log-end>` (or no log-forwarding profile at
all, once profiles are in fixtures) means traffic it passes leaves no trail —
the first thing an incident responder needs is exactly what's missing.
- **Detect:** enabled allow rule where `log-end` text is `no`. PAN-OS defaults
  log-end to yes when the element is absent, so **absent ≠ finding** — that's
  the true-negative test. Use `findtext("./log-end") == "no"` (findtext
  returns None on absence, which never equals `"no"`).
- **Why medium not high:** it passes no extra traffic; it blinds you to the
  traffic it passes.
- **Scaffold in place:** `check_logging_disabled` stub in `audit.py` (steps as
  TODOs, unregistered) + the full test contract in `tests/test_audit.py`,
  skip-marked. To finish: implement the body, register it in `CHECKS`, delete
  the `logging_scaffold` skip marker, `pytest tests/ -q` green.
- **Later:** unlogged deny rules; rules logging locally with no log-forwarding
  profile (needs profile shapes in fixtures first).

### 2. disabled-rule-hygiene  (severity: low)
Disabled rules accumulate — each is a rule someone can re-enable in one click
without change control, and they make the rulebase harder to read.
- **Detect:** any rule where `_is_disabled()` is true. Reuse the helper.
- **True-negative:** an enabled rule with no `<disabled>` element at all.

### 3. shadowed-rule  (severity: medium)
A rule that can never match because an earlier rule already matches everything
it would — dead policy that misleads reviewers. The 2 a.m. emergency rule
placed *above* a specific allow shadows it.
- **Detect (v1, deliberately conservative):** rule B is shadowed if an earlier
  enabled rule A has, for **every** match field (from, to, source, destination,
  service, application), either `any` or a member set that is a superset of
  B's — name-level comparison only, no address-object resolution yet.
- **Superset check on names only** for v1: resolving address objects/groups to
  prefixes is real work (and where this check eventually gets powerful) —
  don't guess ahead; note it as the check's own roadmap line.
- **True-negative:** two rules with disjoint destinations; and a later rule
  *wider* than an earlier one (that's not shadowed).

### 4. broad-service-object  (severity: medium)
Rules that allow `application-default`-bypassing wide service ranges — e.g. a
custom service object spanning huge port ranges, or `service` = `any` with a
scoped app list (app-id still narrows it, hence medium at most).
- **Detect (v1):** enabled allow rule with `service` = `any` and
  `application` ≠ `any` → `low`; custom `<service>` objects in the config whose
  `<port>` spans > 100 ports (parse `<port>0-65535</port>` style values) and
  are referenced by an enabled allow rule → `medium`.
- This is the first check that reads config sections *outside* the rulebase —
  it needs a second extraction helper (`iter_service_objects`), same pattern
  as `iter_security_rules`.

### 5. mgmt-plane-settings  (severity: high)
Management-plane weaknesses live under `<deviceconfig><system>` /
`<service>`, not the rulebase: HTTP or telnet management enabled, SNMP v2c
communities, no login banner.
- **Detect (v1):** `<service><disable-http>no</disable-http>` (or the
  http/telnet service elements present and enabled — verify the exact shape
  against a **real** export first; the doc shapes online are inconsistent and
  this repo's rule is "don't guess ahead of what a lab firewall actually
  shows," per normalize.py).
- **Gate:** this one should not ship until the fixture shape is confirmed
  against real PAN-OS output — same real-gear gate as the collector.

## Later / bigger

- Address-object resolution for shadowed-rule (name superset → prefix
  superset).
- Zone-protection / DoS-profile coverage per zone.
- Findings in the JSON run report (`report.py`) so the observability stack can
  scrape a `panos_audit_findings{severity=...}` metric.
