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
    """Flag enabled allow rules that explicitly disable the session-end log.

    The session-end log carries bytes, application, and duration — what
    incident response reconstructs traffic from. An allow rule with
    <log-end>no</log-end> passes traffic that leaves no trail.

    PAN-OS omits elements at their default value, and log-end defaults to
    YES — so an ABSENT <log-end> element is a rule logging normally and must
    NOT fire (flagging absence would fire on nearly every rule and drown the
    audit in noise). The comparison strips whitespace because a pretty-printed
    export renders the text as "\\n  no\\n" — exact equality would silently
    pass a rule whose logging is off, a false negative in a security check.

    Severity medium, not high: the rule passes no extra traffic; it blinds
    you to the traffic it already passes. Disabled rules and non-allow
    actions are skipped, same reasoning as check_overly_permissive. Unlogged
    deny rules and missing log-forwarding profiles are deliberate later
    extensions — see AUDIT-CHECKS.md.
    """
    findings: list[Finding] = []
    for rule in rules:
        if rule.findtext("./action", default="") != "allow" or _is_disabled(rule):
            continue
        log_end = rule.findtext("./log-end")
        if log_end is None or log_end.strip() != "no":
            continue

        name = rule.get("name") or "<unnamed>"
        findings.append(
            Finding(
                device=device,
                check="logging-disabled",
                severity="medium",
                rule=name,
                detail=(
                    f"allow rule '{name}' has log-end disabled — traffic it passes "
                    f"leaves no session-end log; re-enable log at session end"
                ),
            )
        )
    return findings


def check_disabled_rule_hygiene(device: str, rules: list[ET.Element]) -> list[Finding]:
    """Flag disabled rules. Each one is policy a click away from being live
    again with no change control, and dead entries make the rulebase harder
    to review. Severity low: it passes no traffic today — this is hygiene,
    not exposure. The other checks skip disabled rules precisely because this
    one owns them.
    """
    findings: list[Finding] = []
    for rule in rules:
        if not _is_disabled(rule):
            continue
        name = rule.get("name") or "<unnamed>"
        findings.append(
            Finding(
                device=device,
                check="disabled-rule-hygiene",
                severity="low",
                rule=name,
                detail=(
                    f"rule '{name}' is disabled — one click re-enables it outside "
                    f"change control; delete it or record why it stays"
                ),
            )
        )
    return findings


_MATCH_FIELDS = ("from", "to", "source", "destination", "service", "application")


def _field_covers(a: ET.Element, b: ET.Element, field: str) -> bool:
    """True if rule a's `field` matches everything rule b's `field` matches —
    name-level only: 'any' covers all, otherwise b's members must be a subset
    of a's. Deliberately no address-object/group resolution in v1 (see
    AUDIT-CHECKS.md) — names that differ are treated as disjoint, which can
    only under-report shadowing, never invent it.
    """
    a_members = set(_members(a, field))
    if "any" in a_members:
        return True
    return set(_members(b, field)) <= a_members


def check_shadowed_rule(device: str, rules: list[ET.Element]) -> list[Finding]:
    """Flag rules that can never match: an earlier enabled rule already
    matches everything they would (every match field covered). Security
    policy is first-match top-down, so a fully-covered later rule is dead
    policy — usually the 2 a.m. emergency rule was inserted ABOVE the
    specific rule it now shadows.

    Disabled rules neither shadow nor count as shadowed — they're not in the
    match path (disabled-rule-hygiene owns them). One finding per shadowed
    rule, naming its earliest shadower. Severity medium: nothing extra is
    passed, but the rulebase actively misleads whoever reads it — and if the
    shadower is ever removed, the dead rule silently comes to life.
    """
    findings: list[Finding] = []
    enabled = [r for r in rules if not _is_disabled(r)]
    for position, rule in enumerate(enabled):
        for earlier in enabled[:position]:
            if all(_field_covers(earlier, rule, f) for f in _MATCH_FIELDS):
                name = rule.get("name") or "<unnamed>"
                earlier_name = earlier.get("name") or "<unnamed>"
                findings.append(
                    Finding(
                        device=device,
                        check="shadowed-rule",
                        severity="medium",
                        rule=name,
                        detail=(
                            f"rule '{name}' can never match — '{earlier_name}' earlier "
                            f"in the rulebase already matches everything it would; "
                            f"remove it or move it above '{earlier_name}'"
                        ),
                    )
                )
                break
    return findings


# Registry: audit_config() runs these in order. Add new checks here.
CHECKS = [
    check_overly_permissive,
    check_logging_disabled,
    check_shadowed_rule,
    check_disabled_rule_hygiene,
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
