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
   `audit_config()` and the CLI pick it up automatically. A check that needs
   config sections beyond the rulebase takes them as extra arguments and is
   invoked explicitly in `audit_config()` instead (`check_broad_service_object`
   is the worked example of that variant, with its own extraction helper).
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
`disabled-rule-hygiene`'s job).

### logging-disabled
Enabled `allow` rule with `<log-end>no</log-end>` — traffic it passes leaves
no session-end log (bytes, app, duration: what incident response reconstructs
from). Severity `medium`: it passes no extra traffic, it blinds you to the
traffic it passes. Two traps are load-bearing here, each pinned by a test:
**absent `<log-end>` defaults to YES** and must not fire (PAN-OS omits
defaulted elements — flagging absence fires on nearly every rule), and the
text comparison **strips whitespace** (a pretty-printed export renders
`\n  no\n`; exact equality would false-negative a rule whose logging is off).
Deny rules and disabled rules never fire — v1 scopes to enabled allows.
- **Later:** unlogged deny rules; rules logging locally with no log-forwarding
  profile (needs profile shapes in fixtures first).

### shadowed-rule
A rule that can never match: an earlier **enabled** rule already covers every
match field (from, to, source, destination, service, application) — `any`
covers all, otherwise the later rule's members must be a subset of the
earlier's. First-match top-down makes the covered rule dead policy; the
classic cause is the 2 a.m. emergency rule inserted *above* the specific rule
it now shadows. Severity `medium`: nothing extra is passed, but the rulebase
misleads reviewers — and if the shadower is removed, the dead rule silently
comes to life. One finding per shadowed rule, naming its earliest shadower.
Disabled rules neither shadow nor get flagged (not in the match path).
**v1 is name-level only** — no address-object/group resolution, so unrelated
names read as disjoint: it can under-report shadowing, never invent it.
Direction matters and is test-pinned: a *wider* rule after a specific one is
NOT shadowed.
- **Later:** resolve address objects/groups to prefixes so `{10.0.0.0/8}`
  covers `{10.1.1.5}` (this is where the check gets powerful).

### disabled-rule-hygiene
Any disabled rule, severity `low`: it passes no traffic today, but each one is
policy a click away from live with no change control, and dead entries make
the rulebase harder to review. Owns disabled rules outright — the other checks
skip them for exactly this reason. True-negatives pinned: absent `<disabled>`
and explicit `<disabled>no</disabled>` never fire.

### broad-service-object
Enabled `allow` rule whose service term is effectively unbounded, two shapes:
`service` = `any` with a scoped application list → `low` (App-ID still narrows
what passes, but the rule trusts identification alone instead of pinning
ports — `application-default` is the fix, and as a keyword, not a config
object, it never fires); a referenced custom service object spanning **more
than 100 ports** (port values parsed as `80`, `0-65535`, `80,443,1000-1200`)
→ `medium`. One finding per (rule, object) pair. First check that reads
outside the rulebase: `audit_config()` hands it `iter_service_objects()`
output alongside the rules, invoked explicitly rather than via the CHECKS
registry. Deny and disabled rules never fire; unreferenced broad objects
never fire (unused-object hygiene is not rule risk). **Name-level only,**
like shadowed-rule: service groups aren't expanded and predefined services
never appear in the config's service section — both can only under-report,
never invent. Malformed port values count zero ports, same stance. The
strictly-greater-than-100 boundary is test-pinned (100 quiet, 101 fires).
- **Later:** expand `<service-group>` membership so a broad object hidden
  behind a group is caught; `service any` + `application any` on scoped
  endpoints (today it falls between this check and overly-permissive-rule,
  which requires any/any endpoints).

## Planned — build these next, in this order

### 1. mgmt-plane-settings  (severity: high)
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
  superset) — tracked under that check's own Later bullet above.
- Zone-protection / DoS-profile coverage per zone.
- Findings in the JSON run report (`report.py`) so the observability stack can
  scrape a `panos_audit_findings{severity=...}` metric.
