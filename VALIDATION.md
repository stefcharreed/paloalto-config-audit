# VALIDATION.md — real-gear validation runbook

The roadmap's gate line: **nothing in this repo is called "working" until the live
path has run against real PAN-OS.** Fixtures prove logic; real gear proves it works.
This runbook is the first-contact session against a lab firewall (and optionally
Panorama), step by step, with the specific untested assumption each step validates.
Record results in the matrix at the bottom, then flip the roadmap checkbox and the
CLAUDE.md "NOTHING here is hardware-validated yet" note.

Everything here is **read-only against the firewall** — `backup`, `diff`, `audit`,
and `report` never write to the device. The only writes are git commits into your
private snapshots/baselines repo.

## Prerequisites

- A lab firewall running PAN-OS (or Panorama with a device group), reachable from
  this machine.
- An admin account on it that can generate an API key. Prefer a dedicated
  least-privilege role (XML API + configuration **read** only) over your superuser —
  the key lands in `secrets.env` on disk.
- This repo installed (`pip install -e ".[dev]"`) and the offline suite green
  (`pytest tests/ -q`).
- A **separate, private** git repo to hold snapshots/baselines (the configure wizard
  validates this — it must be an existing git working tree outside this code repo).
  Real PAN-OS configs are the security policy itself; they never enter this repo.

## Safety notes before touching gear

- `verify=False` in the collector is **lab-only** (THREAT-MODEL.md AR-1). Fine for
  this session against your own lab box; pin a CA bundle before any use beyond it.
- The API key goes in the `X-PAN-KEY` header — that's the code path under test.
  When *generating* the key (step 1), use a POST body, not a GET query string, so
  the password doesn't land in any access log.
- `secrets.env` is gitignored — confirm with `git status` after step 3 anyway.

## The session

Run steps in order; each has an expected outcome and the assumption it validates.

### 1. Generate the API key

```
curl -sk -X POST 'https://<FW-MGMT-IP>/api/?type=keygen' \
  --data-urlencode 'user=<API-USER>' --data-urlencode 'password=<PASSWORD>'
```

Expected: `<response status="success">` with a `<key>` element.
Validates: nothing in this repo yet — just gets you the credential.

### 2. `panos-audit configure`

Point the wizard at your private snapshots/baselines repo root; accept the offered
`snapshots/`/`baselines/`/`reports/` subdirectories. Add the lab device to
`config/config.yaml` (management IP, name).

Expected: wizard accepts the root (existing git tree, outside this repo).
Validates: the configure flow against a real filesystem/repo layout.

### 3. First live pull — `panos-audit backup <DEVICE>`

The first-run secrets wizard fires here (backup touches live gear); paste the key.

Expected: one `<device>.xml` written into `snapshots/` and committed to the private
repo; `git log <device>.xml` shows the commit.
**This is the core of the whole session.** Validates, in one shot:
- the API key is accepted from the `X-PAN-KEY` header (not query string),
- the xpath/config-export request shape is what real PAN-OS expects,
- the response envelope parses the way the fixtures assumed,
- gitstore's commit path works against a real private repo.

If this step fails, capture the exact HTTP status and response body — the fix is
almost certainly in `collector.py`'s request shape, and the error text is the spec.

### 4. Negative test — wrong key

Temporarily put a garbage key in `secrets.env`, run `backup` again.

Expected: a clear, single-line failure (PAN-OS returns HTTP 403 / an error
envelope), not a traceback and not a zero-byte "backup" committed to the repo.
Validates: the collector's error path distinguishes auth failure from success —
a silent bad-auth "backup" would poison the timeline. Restore the real key after.

### 5. `panos-audit diff`

Expected: `NO BASELINE` (cyan) for the device — not `DRIFT`.
Validates: the no-baseline-vs-drift distinction on a real config, and that
normalize handles a real PAN-OS export (any `UserWarning` here means real exports
don't parse the way fixtures do — that's a finding, not noise).

### 6. `panos-audit promote <DEVICE>` then `diff` again

Approve at the y/N gate, then re-run diff.

Expected: promote commits the baseline; second diff reports clean.
Validates: the promote plan/apply flow and that normalize is stable on real XML —
**run `backup` + `diff` once more with no changes on the firewall; it must still be
clean.** Phantom drift on an unchanged device is the #1 thing fixtures can't prove.

### 7. Real drift — benign change

On the firewall, make one harmless change (edit a rule description / add a tag),
commit it on the box, then `backup` + `diff`.

Expected: `DRIFT`, and the delta shows *that change and nothing else*.
Validates: end-to-end drift detection signal quality — one real change produces one
focused delta, not an XML avalanche.

### 8. `panos-audit audit`

Expected: findings (or clean) from overly-permissive-rule and logging-disabled
against the real rulebase; no crash on real-export XML shapes.
Validates: the check framework on a real config. Note anything surprising in how
PAN-OS renders defaulted elements — the mgmt-plane check (AUDIT-CHECKS.md) is
gated on exactly these observations.

### 9. `panos-audit report`

Expected: JSON summary written to `reports/`, drift state matching step 7.
Validates: the pull → drift-check → JSON path (report does not write backups).

### 10. (If available) Panorama / device group

Repeat steps 3–7 through Panorama with a `device_group` set.

Expected: same behaviors via the Panorama xpath.
Validates: the device-group request shape — the least-exercised branch in the
collector.

## Results matrix

Fill in as you go; this table is the evidence the roadmap checkbox points at.

| # | Live-path assumption | Step | Result (date, PAN-OS version, notes) |
| - | -------------------- | ---- | ------------------------------------ |
| 1 | X-PAN-KEY header auth accepted | 3 | |
| 2 | Config-export request shape correct | 3 | |
| 3 | Response envelope parses | 3 | |
| 4 | Auth failure is loud, nothing committed | 4 | |
| 5 | Real export normalizes without warnings | 5 | |
| 6 | No phantom drift on unchanged device | 6 | |
| 7 | One real change → one focused delta | 7 | |
| 8 | Audit checks run on real rulebase | 8 | |
| 9 | Report JSON correct against real state | 9 | |
| 10 | Panorama device-group path | 10 | |

## After the session

1. Fill the matrix above and commit it (results are publish-safe: date, PAN-OS
   version, pass/fail, sanitized notes — no IPs, no hostnames, no key material).
2. Flip the README roadmap line and update CLAUDE.md's "NOTHING here is
   hardware-validated yet" section to say what *was* validated, on what, and when.
3. Anything that failed becomes an issue/fix — the offline suite gets a regression
   test shaped like the real-gear failure before the fix lands.
