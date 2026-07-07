#!/usr/bin/env python3
"""
sanitize_check.py — scan a PAN-OS config export for content unsafe to commit
to a public repo.

A config is "safe to publish" only if it uses RFC 5737 documentation IPs and
exposes no API keys or admin password hashes. Mirrors netmiko-config-audit's
sanitize_check.py, adapted for PAN-OS's XML shape and secret encodings.
This is a guard, not the audit tool: run it before a sample config earns a
place in tests/fixtures/.
"""

import ipaddress
import re
import sys

DOC_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]
_THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")
IPV4_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

# PAN-OS stores admin passwords as a <phash> element (crypt-style hash) and API
# keys as long base64-ish tokens (LUFRPT... prefix on newer PAN-OS).
CREDENTIAL_PATTERNS = [
    re.compile(r"<phash>[^<]+</phash>"),
    re.compile(r"<password>[^<]+</password>"),      # pre-shared keys, IPSec, etc.
    re.compile(r"\bLUFRPT[A-Za-z0-9+/=]{10,}"),      # PAN-OS API key prefix
]


def _check_real_ips(line: str) -> list[dict]:
    findings = []
    for candidate in IPV4_PATTERN.findall(line):
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue

        if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_reserved:
            continue
        if candidate.startswith("255."):
            continue
        if ip in _THIS_NETWORK:
            continue
        if any(ip in net for net in DOC_NETWORKS):
            continue

        if ip.is_private:
            findings.append({
                "category": "private_ip",
                "detail": f"{candidate} is RFC 1918 private space — real topology; "
                          f"use a 5737 doc range",
            })
        else:
            findings.append({
                "category": "real_ip",
                "detail": f"{candidate} is a real-looking public IP — not in an "
                          f"RFC 5737 doc range",
            })
    return findings


def _check_credentials(line: str) -> list[dict]:
    for pattern in CREDENTIAL_PATTERNS:
        if pattern.search(line):
            return [{
                "category": "credential",
                "detail": "line contains a password hash, pre-shared key, or API "
                          "key — fixtures must have zero real secrets",
            }]
    return []


def check_config(config_text: str) -> list[dict]:
    """Scan a config for content unsafe to commit to a public repo.

    Returns a list of finding dicts (empty list == clean). Each finding:
        {"line_number": int, "line": str, "category": str, "detail": str}
    """
    checks = (_check_real_ips, _check_credentials)
    findings = []
    for line_number, raw_line in enumerate(config_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        for check in checks:
            for finding in check(line):
                finding["line_number"] = line_number
                finding["line"] = line
                findings.append(finding)
    return findings


def _print_report(path: str, findings: list[dict]) -> None:
    if not findings:
        print(f"OK  {path}: clean — safe to commit")
        return
    print(f"FAIL  {path}: {len(findings)} issue(s) found\n")
    for f in findings:
        print(f"  line {f['line_number']:>4}  [{f['category']}]  {f['line']}")
        print(f"             -> {f['detail']}")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python sanitize_check.py <config-file>")
        return 2
    path = sys.argv[1]
    with open(path, encoding="utf-8") as fh:
        config_text = fh.read()
    findings = check_config(config_text)
    _print_report(path, findings)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
