# Threat model

Written 2026-07-07, before first push (per the standing rule: threat model
before the repo goes public). Short by design — assets, attackers, boundaries,
and dated accepted risks.

## Assets

1. **The PAN-OS API key** (`secrets.env`, runtime only). Administrative access
   to the firewall/Panorama — the single most valuable secret this tool touches.
2. **Pulled firewall configs** (private backup repo). A real config reveals the
   security policy itself: what's allowed, what's not, addressing, zones — a
   literal attack map. More sensitive than the router configs the sibling tool
   handles.
3. **The baseline repo's integrity.** Git history is the audit trail of who
   approved which policy as intended state; corrupt it and drift detection
   reports against the wrong truth.
4. **This public repo's cleanliness.** History is permanent; one leaked config
   or key in a commit is unrecoverable by deletion.

## Who would attack, and where

| Attacker | Vector |
|---|---|
| Anyone scraping public GitHub | Secrets/configs accidentally committed here |
| Someone with access to web/proxy logs in the path | Credentials in URLs (mitigated 2026-07-07: key moved to the X-PAN-KEY header) |
| On-path attacker between tool and firewall | TLS interception — see accepted risk AR-1 |
| Someone with write access to the backup/baseline repo | Rewriting "intended state" so real drift reads as in-sync |

## Trust boundaries

- **Public repo ↔ private data.** Nothing real crosses into this repo:
  `.gitignore` + `scripts/pre-commit` + `sanitize_check.py` enforce it, and
  committed fixtures must pass the sanitizer (tested in CI).
- **Tool ↔ firewall/Panorama.** HTTPS with an API key. The tool only ever
  *reads* config in v1 — there is no write path to the firewall yet, which is
  itself a security property (a compromised run can leak state but not change
  policy). Revisit this section before any `push`-equivalent lands.
- **Operator ↔ baseline.** Baselines are hand-authored for now (no `promote`
  gate yet) — the human approval step exists but isn't tool-enforced. Roadmap.

## Accepted risks (dated)

- **AR-1 (2026-07-07): `verify=False` on collector HTTPS calls.** Firewalls and
  Panorama in the lab run self-signed certs. Accepted **only while the tool
  points at lab gear**; pinning a real cert or internal CA bundle is a blocker
  for production use. The urllib3 InsecureRequestWarning is left unsuppressed
  on purpose — the noise is the reminder.
- **AR-2 (2026-07-07): API key grants read of full config.** PAN-OS key scoping
  (admin roles / API permission profiles) is not yet configured or documented
  here; the tool works with whatever key it's given. Mitigation for now:
  generate the key from a read-only admin role. Documenting a least-privilege
  role profile is on the roadmap.
