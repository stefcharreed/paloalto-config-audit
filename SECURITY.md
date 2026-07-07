# Security

If you find a vulnerability in this tool (e.g. a way to make it leak the API key,
write outside its configured directories, or evade the sanitizer/pre-commit gate),
please report it privately via [GitHub's private vulnerability reporting](../../security/advisories/new)
rather than a public issue. You'll get a response within a week.

Notes on scope:

- This repo contains no live infrastructure, credentials, or real firewall data —
  the API key and config backups live outside the repo by design (`secrets.env`
  and the backup repo are gitignored). A report that a *fixture* contains a secret
  is still welcome: fixtures are required to be fully sanitized (RFC 5737
  addresses, fake names, no hashes or keys) and a lapse there is a bug.
- The tool talks to firewalls/Panorama with an API key you supply at runtime.
  Treat the machine running it, and its `secrets.env`, with the same care as the
  firewalls themselves — a PAN-OS API key is administrative access.
- Known accepted risk: TLS verification is currently disabled in the collector
  (lab-only; dated decision in THREAT-MODEL.md). Reports about that are
  acknowledged, not news.
