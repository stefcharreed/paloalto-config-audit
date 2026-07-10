"""Rulebase security audit: inspect a config for risky policy, not just drift.

Drift asks "did this firewall change from its approved state?" — this module
asks the complementary question: "is the state itself risky?" A baseline can be
faithfully in sync and still contain an any/any allow rule someone approved at
2 a.m.; drift detection will never flag that, an audit will.

Same seam discipline as every other module here: functions take config text /
parsed data and return plain JSON-serializable findings — no printing, no rich,
no file writes. Rendering lives in cli.py's _cmd_audit.

Check registry pattern: each check is a function
    (device_name, rules) -> list[Finding]
registered in CHECKS. `audit_config()` parses once and runs every registered
check. To add a check, write the function and add it to CHECKS — nothing else
changes. AUDIT-CHECKS.md specs the checks planned but not yet implemented;
`check_overly_permissive` below is the worked example they should follow.

Rule extraction uses `.//security/rules/entry`, which matches a firewall's
`rulebase`, and Panorama's `pre-rulebase`/`post-rulebase` — all three carry
security rules that are live policy.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass


@dataclass
class Finding:
    """One audit finding, JSON-serializable via to_dict()."""

    device: str
    check: str      # stable slug, e.g. "overly-permissive-rule" — report keys off it
    severity: str   # "high" | "medium" | "low"
    rule: str | None  # security-rule name, or None for config-level findings
    detail: str     # one line a firewall engineer can act on

    def to_dict(self) -> dict:
        return asdict(self)


def _members(entry: ET.Element, tag: str) -> list[str]:
    """The <member> values of a rule field, e.g. _members(rule, 'source').

    PAN-OS renders every rule field as <tag><member>...</member>...</tag>,
    including single values — 'any' is a literal <member>any</member>.
    """
    return [m.text or "" for m in entry.findall(f"./{tag}/member")]


def _is_disabled(entry: ET.Element) -> bool:
    disabled = entry.find("./disabled")
    return disabled is not None and (disabled.text or "").strip() == "yes"


def iter_security_rules(config_text: str) -> list[ET.Element]:
    """Parse `config_text` and return every security-rule <entry>, in policy
    order. Raises ET.ParseError on malformed XML — audit_config() turns that
    into a finding rather than swallowing it, because an audit that silently
    reports 'clean' on an unparseable config is worse than no audit.
    """
    root = ET.fromstring(config_text)
    return root.findall(".//security/rules/entry")


def check_overly_permissive(device: str, rules: list[ET.Element]) -> list[Finding]:
    """Flag enabled allow rules whose source AND destination are both 'any'.

    This is the worked-example check — the shape every future check in
    AUDIT-CHECKS.md should follow: iterate the rules, apply one narrow test,
    return Findings with a stable check slug.

    An any/any *deny* is normal (the cleanup rule at the bottom of the
    rulebase); an any/any *allow* is the classic emergency rule that never got
    removed. If service and application are also 'any' the rule passes
    literally everything, so severity escalates to high. Disabled rules are
    skipped here — they pass no traffic; their hygiene is a separate planned
    check (see AUDIT-CHECKS.md, disabled-rule-hygiene).
    """
    findings: list[Finding] = []
    for rule in rules:
        action = rule.findtext("./action", default="")
        if action != "allow" or _is_disabled(rule):
            continue
        if _members(rule, "source") != ["any"] or _members(rule, "destination") != ["any"]:
            continue

        name = rule.get("name") or "<unnamed>"
        wide_open = (
            _members(rule, "service") == ["any"]
            and _members(rule, "application") == ["any"]
        )
        findings.append(
            Finding(
                device=device,
                check="overly-permissive-rule",
                severity="high" if wide_open else "medium",
                rule=name,
                detail=(
                    f"allow rule '{name}' matches any source to any destination"
                    + (
                        " with any service and any application — passes all traffic"
                        if wide_open
                        else " — scope the source or destination"
                    )
                ),
            )
        )
    return findings


def check_logging_disabled(device: str, rules: list[ET.Element]) -> list[Finding]:
    """SCAFFOLD — spec in AUDIT-CHECKS.md (logging-disabled); tests already
    written in tests/test_audit.py (skip-marked). To finish: implement the body,
    add this function to CHECKS below, remove the skip marker, run pytest.

    Flag enabled allow rules with <log-end>no</log-end> — traffic they pass
    leaves no session-end log, which is exactly what incident response needs.

    THE TRAP: PAN-OS omits elements at their default, and log-end defaults to
    YES — so an ABSENT <log-end> element means logging is fine and must NOT
    fire. Detect `findtext("./log-end") == "no"` (findtext returns None when
    absent, which never equals "no"). Flagging absence would fire on nearly
    every rule and drown the audit in noise.

    Severity medium: the rule passes no extra traffic; it blinds you to the
    traffic it already passes. check slug: "logging-disabled" (stable once
    shipped). Skip disabled rules and non-allow actions, same reasoning as
    check_overly_permissive.
    """
    findings: list[Finding] = []
    # TODO(stefan): iterate `rules`; for each rule:
    #   1) skip disabled rules (_is_disabled) and non-allow actions
    #   2) fire only when log-end is PRESENT with text "no"
    #   3) append a Finding(check="logging-disabled", severity="medium",
    #      rule=<name>, detail=<one actionable line>)
    return findings


# Registry: audit_config() runs these in order. Add new checks here.
CHECKS = [
    check_overly_permissive,
    # TODO(stefan): register check_logging_disabled once implemented
]


def audit_config(device_name: str, config_text: str) -> list[Finding]:
    """Run every registered check against one device's config text.

    Empty text returns no findings — that's the known "no backup yet" state,
    and the CLI (which can see the filesystem) renders it distinctly, same as
    diff's NO BASELINE handling. Unparseable text returns a single high-severity
    unparseable-config finding instead of raising: the collector likely returned
    an error page, and "audit clean" must never be the report for that.
    """
    if not config_text.strip():
        return []
    try:
        rules = iter_security_rules(config_text)
    except ET.ParseError as exc:
        return [
            Finding(
                device=device_name,
                check="unparseable-config",
                severity="high",
                rule=None,
                detail=(
                    f"config is not parseable XML ({exc}) — if this came from a live "
                    f"device, the collector likely returned an error page, not a config"
                ),
            )
        ]

    findings: list[Finding] = []
    for check in CHECKS:
        findings.extend(check(device_name, rules))
    return findings
