"""Rulebase audit checks against the committed fixtures.

The drift fixture doubles as the audit's true-positive case: its
temp-emergency-access rule is a literal any/any/any/any allow, and its
allow-web rule is a service-any-with-scoped-app (broad-service-object, low).
The baseline fixture is the true-negative case — its any/any rule is the
deny-all cleanup rule, which must NOT fire the permissive check, and its
allow-web pins service-https.
"""
import xml.etree.ElementTree as ET
from pathlib import Path

from panos_audit.audit import (
    Finding,
    audit_config,
    check_broad_service_object,
    check_disabled_rule_hygiene,
    check_logging_disabled,
    check_overly_permissive,
    check_shadowed_rule,
    iter_security_rules,
    iter_service_objects,
)

FIXTURES = Path(__file__).parent / "fixtures"
BASELINE = (FIXTURES / "fw1_baseline.xml").read_text(encoding="utf-8")
DRIFTED = (FIXTURES / "fw1_current_drift.xml").read_text(encoding="utf-8")


def _rule(xml: str) -> ET.Element:
    return ET.fromstring(xml)


def test_clean_rulebase_yields_no_findings():
    assert audit_config("fw1", BASELINE) == []


def test_drift_fixture_findings_are_exactly_these():
    """The drift fixture carries two audit-relevant shapes: the any/any/any/any
    temp-emergency-access allow (overly-permissive, high) and allow-web's
    service-any-with-scoped-app (broad-service-object, low). Pinning the full
    list keeps a new check from silently changing what this fixture means."""
    findings = audit_config("fw1", DRIFTED)
    assert [(f.check, f.rule, f.severity) for f in findings] == [
        ("overly-permissive-rule", "temp-emergency-access", "high"),
        ("broad-service-object", "allow-web", "low"),
    ]


def test_any_any_deny_does_not_fire():
    """The cleanup rule at the bottom of every rulebase is any/any deny —
    flagging it would bury real findings in noise on every single device."""
    rules = iter_security_rules(BASELINE)
    deny_all = [r for r in rules if r.get("name") == "deny-all"]
    assert deny_all, "fixture must contain the deny-all cleanup rule"
    assert check_overly_permissive("fw1", deny_all) == []


def test_scoped_service_downgrades_to_medium():
    rule = _rule(
        """<entry name="broad-but-scoped-service">
             <from><member>untrust</member></from><to><member>trust</member></to>
             <source><member>any</member></source>
             <destination><member>any</member></destination>
             <service><member>service-https</member></service>
             <application><member>web-browsing</member></application>
             <action>allow</action>
           </entry>"""
    )
    findings = check_overly_permissive("fw1", [rule])
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_disabled_rule_is_skipped():
    rule = _rule(
        """<entry name="old-emergency-rule">
             <source><member>any</member></source>
             <destination><member>any</member></destination>
             <service><member>any</member></service>
             <application><member>any</member></application>
             <action>allow</action>
             <disabled>yes</disabled>
           </entry>"""
    )
    assert check_overly_permissive("fw1", [rule]) == []


def test_empty_config_is_the_no_backup_state_not_a_finding():
    assert audit_config("fw1", "") == []


def test_unparseable_config_is_a_high_finding_never_clean():
    findings = audit_config("fw1", "<html>502 Bad Gateway</html><oops")
    assert len(findings) == 1
    assert findings[0].check == "unparseable-config"
    assert findings[0].severity == "high"


def test_finding_serializes_to_plain_dict():
    """Seam discipline: findings must survive json.dumps for report.py reuse."""
    import json

    f = Finding(device="fw1", check="x", severity="low", rule=None, detail="d")
    assert json.loads(json.dumps(f.to_dict()))["device"] == "fw1"


# --- logging-disabled --------------------------------------------------------

def test_log_end_no_on_allow_rule_is_flagged_medium():
    rule = _rule(
        """<entry name="chatty-app-allow">
             <source><member>branch-lan</member></source>
             <destination><member>web-srv-1</member></destination>
             <service><member>service-https</member></service>
             <application><member>web-browsing</member></application>
             <action>allow</action>
             <log-end>no</log-end>
           </entry>"""
    )
    findings = check_logging_disabled("fw1", [rule])
    assert len(findings) == 1
    assert findings[0].check == "logging-disabled"
    assert findings[0].severity == "medium"
    assert findings[0].rule == "chatty-app-allow"


def test_absent_log_end_defaults_to_yes_and_does_not_fire():
    """THE load-bearing true-negative: PAN-OS omits defaulted elements, and
    log-end defaults to YES — an absent element is a rule logging normally.
    Flagging absence would fire on nearly every rule in every config."""
    rule = _rule(
        """<entry name="allow-web">
             <source><member>any</member></source>
             <destination><member>web-srv-1</member></destination>
             <service><member>service-https</member></service>
             <application><member>web-browsing</member></application>
             <action>allow</action>
           </entry>"""
    )
    assert check_logging_disabled("fw1", [rule]) == []


def test_deny_rule_without_logging_does_not_fire_in_v1():
    """v1 scopes to allow rules only — unlogged denies are a real visibility
    gap but a deliberate later extension (see AUDIT-CHECKS.md)."""
    rule = _rule(
        """<entry name="deny-all">
             <source><member>any</member></source>
             <destination><member>any</member></destination>
             <action>deny</action>
             <log-end>no</log-end>
           </entry>"""
    )
    assert check_logging_disabled("fw1", [rule]) == []


def test_disabled_rule_with_log_end_no_is_skipped():
    rule = _rule(
        """<entry name="old-rule">
             <source><member>any</member></source>
             <destination><member>web-srv-1</member></destination>
             <action>allow</action>
             <log-end>no</log-end>
             <disabled>yes</disabled>
           </entry>"""
    )
    assert check_logging_disabled("fw1", [rule]) == []


def test_logging_disabled_is_registered_and_reachable_via_audit_config():
    """Once registered in CHECKS, audit_config() must surface the finding
    end-to-end — a check that exists but isn't registered never runs."""
    config = """<config><devices><entry name="fw"><vsys><entry name="vsys1">
        <rulebase><security><rules>
          <entry name="quiet-allow">
            <source><member>branch-lan</member></source>
            <destination><member>web-srv-1</member></destination>
            <service><member>service-https</member></service>
            <application><member>web-browsing</member></application>
            <action>allow</action>
            <log-end>no</log-end>
          </entry>
        </rules></security></rulebase>
    </entry></vsys></entry></devices></config>"""
    findings = audit_config("fw1", config)
    assert [f.check for f in findings] == ["logging-disabled"]


def test_explicit_log_end_yes_does_not_fire():
    """Guards against a presence-only implementation: <log-end>yes</log-end>
    written out explicitly is a rule logging normally — the element existing
    is not the finding, its value being 'no' is."""
    rule = _rule(
        """<entry name="explicit-logging">
             <source><member>branch-lan</member></source>
             <destination><member>web-srv-1</member></destination>
             <action>allow</action>
             <log-end>yes</log-end>
           </entry>"""
    )
    assert check_logging_disabled("fw1", [rule]) == []


def test_pretty_printed_log_end_no_still_fires():
    """A formatted export renders the text as '\\n  no\\n' — exact string
    equality would silently pass a rule whose logging is off (a false
    negative in a security check). The comparison must strip."""
    rule = _rule(
        """<entry name="formatted-rule">
             <source><member>branch-lan</member></source>
             <destination><member>web-srv-1</member></destination>
             <action>allow</action>
             <log-end>
               no
             </log-end>
           </entry>"""
    )
    findings = check_logging_disabled("fw1", [rule])
    assert [f.rule for f in findings] == ["formatted-rule"]


def test_multiple_quiet_rules_each_get_a_finding_in_policy_order():
    quiet = """<entry name="{name}">
                 <source><member>branch-lan</member></source>
                 <destination><member>web-srv-1</member></destination>
                 <action>allow</action>
                 <log-end>no</log-end>
               </entry>"""
    rules = [
        _rule(quiet.format(name="first-quiet")),
        _rule(
            """<entry name="fine-rule">
                 <source><member>branch-lan</member></source>
                 <destination><member>web-srv-1</member></destination>
                 <action>allow</action>
               </entry>"""
        ),
        _rule(quiet.format(name="second-quiet")),
    ]
    findings = check_logging_disabled("fw1", rules)
    assert [f.rule for f in findings] == ["first-quiet", "second-quiet"]


def test_unnamed_rule_gets_placeholder_not_none():
    """A rule entry missing its name attribute must still produce a readable
    finding — same placeholder convention as check_overly_permissive."""
    rule = _rule(
        """<entry>
             <source><member>branch-lan</member></source>
             <destination><member>web-srv-1</member></destination>
             <action>allow</action>
             <log-end>no</log-end>
           </entry>"""
    )
    findings = check_logging_disabled("fw1", [rule])
    assert len(findings) == 1
    assert findings[0].rule == "<unnamed>"
    assert "None" not in findings[0].detail


# --- disabled-rule-hygiene -----------------------------------------------------

def test_disabled_rule_is_flagged_low():
    rule = _rule(
        """<entry name="old-rule">
             <source><member>branch-lan</member></source>
             <destination><member>web-srv-1</member></destination>
             <action>allow</action>
             <disabled>yes</disabled>
           </entry>"""
    )
    findings = check_disabled_rule_hygiene("fw1", [rule])
    assert len(findings) == 1
    assert findings[0].check == "disabled-rule-hygiene"
    assert findings[0].severity == "low"
    assert findings[0].rule == "old-rule"


def test_enabled_rules_do_not_fire_hygiene():
    """Neither an absent <disabled> element nor an explicit <disabled>no</disabled>
    is a finding — only actually-disabled rules are."""
    absent = _rule(
        """<entry name="normal-rule">
             <source><member>branch-lan</member></source>
             <destination><member>web-srv-1</member></destination>
             <action>allow</action>
           </entry>"""
    )
    explicit_no = _rule(
        """<entry name="explicit-enabled">
             <source><member>branch-lan</member></source>
             <destination><member>web-srv-1</member></destination>
             <action>allow</action>
             <disabled>no</disabled>
           </entry>"""
    )
    assert check_disabled_rule_hygiene("fw1", [absent, explicit_no]) == []


def test_disabled_any_any_allow_fires_hygiene_only():
    """The checks divide the work: a disabled any/any allow is exactly one
    hygiene finding — permissive/logging/shadow all skip disabled rules
    because this check owns them."""
    config = """<config><devices><entry name="fw"><vsys><entry name="vsys1">
        <rulebase><security><rules>
          <entry name="old-emergency">
            <source><member>any</member></source>
            <destination><member>any</member></destination>
            <service><member>any</member></service>
            <application><member>any</member></application>
            <action>allow</action>
            <log-end>no</log-end>
            <disabled>yes</disabled>
          </entry>
        </rules></security></rulebase>
    </entry></vsys></entry></devices></config>"""
    findings = audit_config("fw1", config)
    assert [f.check for f in findings] == ["disabled-rule-hygiene"]


# --- shadowed-rule ---------------------------------------------------------------

WIDE_OPEN = """<entry name="catch-everything">
                 <from><member>any</member></from><to><member>any</member></to>
                 <source><member>any</member></source>
                 <destination><member>any</member></destination>
                 <service><member>any</member></service>
                 <application><member>any</member></application>
                 <action>allow</action>
               </entry>"""

SPECIFIC = """<entry name="allow-web">
                <from><member>untrust</member></from><to><member>trust</member></to>
                <source><member>branch-lan</member></source>
                <destination><member>web-srv-1</member></destination>
                <service><member>service-https</member></service>
                <application><member>web-browsing</member></application>
                <action>allow</action>
              </entry>"""


def test_rule_after_wide_open_rule_is_shadowed():
    findings = check_shadowed_rule("fw1", [_rule(WIDE_OPEN), _rule(SPECIFIC)])
    assert len(findings) == 1
    f = findings[0]
    assert f.check == "shadowed-rule"
    assert f.severity == "medium"
    assert f.rule == "allow-web"
    assert "catch-everything" in f.detail


def test_wider_rule_after_specific_rule_is_not_shadowed():
    """First-match top-down: the wide rule still matches everything the
    specific one doesn't — shadowing is directional."""
    assert check_shadowed_rule("fw1", [_rule(SPECIFIC), _rule(WIDE_OPEN)]) == []


def test_identical_duplicate_rule_is_shadowed():
    dup = SPECIFIC.replace('name="allow-web"', 'name="allow-web-copy"')
    findings = check_shadowed_rule("fw1", [_rule(SPECIFIC), _rule(dup)])
    assert [f.rule for f in findings] == ["allow-web-copy"]


def test_disjoint_rules_do_not_shadow():
    other = SPECIFIC.replace("web-srv-1", "db-srv-1").replace(
        'name="allow-web"', 'name="allow-db"'
    )
    assert check_shadowed_rule("fw1", [_rule(SPECIFIC), _rule(other)]) == []


def test_member_subset_shadows_without_any():
    """Coverage is subset-based, not just 'any': {branch-lan} sits inside
    {branch-lan, dmz-lan} on every differing field."""
    wider = SPECIFIC.replace(
        "<source><member>branch-lan</member></source>",
        "<source><member>branch-lan</member><member>dmz-lan</member></source>",
    ).replace('name="allow-web"', 'name="allow-web-both-lans"')
    findings = check_shadowed_rule("fw1", [_rule(wider), _rule(SPECIFIC)])
    assert [f.rule for f in findings] == ["allow-web"]


def test_disabled_rules_neither_shadow_nor_get_flagged():
    disabled_wide = _rule(WIDE_OPEN.replace("</entry>", "<disabled>yes</disabled></entry>"))
    assert check_shadowed_rule("fw1", [disabled_wide, _rule(SPECIFIC)]) == []
    disabled_specific = _rule(SPECIFIC.replace("</entry>", "<disabled>yes</disabled></entry>"))
    assert check_shadowed_rule("fw1", [_rule(WIDE_OPEN), disabled_specific]) == []


def test_one_finding_per_shadowed_rule_naming_earliest_shadower():
    """Two wide rules above a victim: the second wide rule is itself shadowed
    by the first, and the victim reports the EARLIEST shadower once — not one
    finding per shadower."""
    second_wide = WIDE_OPEN.replace('name="catch-everything"', 'name="also-everything"')
    findings = check_shadowed_rule(
        "fw1", [_rule(WIDE_OPEN), _rule(second_wide), _rule(SPECIFIC)]
    )
    assert [f.rule for f in findings] == ["also-everything", "allow-web"]
    assert all("'catch-everything'" in f.detail for f in findings)


def test_panorama_pre_rulebase_rules_are_found():
    """`.//security/rules/entry` must match pre-rulebase too, not just rulebase."""
    config = """<config><devices><entry name="pano"><device-group><entry name="dg1">
        <pre-rulebase><security><rules>
          <entry name="dg-allow-all">
            <source><member>any</member></source>
            <destination><member>any</member></destination>
            <service><member>any</member></service>
            <application><member>any</member></application>
            <action>allow</action>
          </entry>
        </rules></security></pre-rulebase>
    </entry></device-group></entry></devices></config>"""
    findings = audit_config("pano", config)
    assert [f.rule for f in findings] == ["dg-allow-all"]


# --- broad-service-object ----------------------------------------------------

def _svc(name: str, port: str) -> ET.Element:
    """A custom service object as it renders in the config's service section."""
    return ET.fromstring(
        f"""<entry name="{name}">
              <protocol><tcp><port>{port}</port></tcp></protocol>
            </entry>"""
    )


BROAD_REF_RULE = """<entry name="just-make-it-work">
     <from><member>trust</member></from><to><member>dmz</member></to>
     <source><member>branch-lan</member></source>
     <destination><member>web-srv-1</member></destination>
     <service><member>tcp-all</member></service>
     <application><member>any</member></application>
     <action>allow</action>
   </entry>"""


def test_service_any_with_scoped_apps_flags_low():
    rule = _rule(
        """<entry name="app-id-only">
             <source><member>branch-lan</member></source>
             <destination><member>web-srv-1</member></destination>
             <service><member>any</member></service>
             <application><member>web-browsing</member><member>ssl</member></application>
             <action>allow</action>
           </entry>"""
    )
    findings = check_broad_service_object("fw1", [rule], [])
    assert [(f.check, f.severity, f.rule) for f in findings] == [
        ("broad-service-object", "low", "app-id-only")
    ]


def test_service_any_with_application_any_does_not_fire():
    """Not this check's finding: with any endpoints that rule is
    overly-permissive-rule's high; with scoped endpoints it's a logged v1
    gap (AUDIT-CHECKS.md, Later) — 'a scoped app list' is the spec's clause,
    and application any is not one."""
    rule = _rule(
        """<entry name="scoped-endpoints-any-everything">
             <source><member>branch-lan</member></source>
             <destination><member>web-srv-1</member></destination>
             <service><member>any</member></service>
             <application><member>any</member></application>
             <action>allow</action>
           </entry>"""
    )
    assert check_broad_service_object("fw1", [rule], []) == []


def test_application_default_service_does_not_fire():
    """application-default is the FIX this check recommends — it's a keyword,
    not a config object, so it can never appear in the span map."""
    rule = _rule(
        """<entry name="pinned-to-app-default">
             <source><member>branch-lan</member></source>
             <destination><member>web-srv-1</member></destination>
             <service><member>application-default</member></service>
             <application><member>web-browsing</member></application>
             <action>allow</action>
           </entry>"""
    )
    assert check_broad_service_object("fw1", [rule], []) == []


def test_broad_custom_object_on_enabled_allow_flags_medium():
    findings = check_broad_service_object(
        "fw1", [_rule(BROAD_REF_RULE)], [_svc("tcp-all", "0-65535")]
    )
    assert [(f.severity, f.rule) for f in findings] == [("medium", "just-make-it-work")]
    assert "'tcp-all'" in findings[0].detail
    assert "65536 ports" in findings[0].detail


def test_port_span_boundary_100_does_not_fire_101_does():
    """The threshold is STRICTLY greater than 100 ports — a 100-port range is
    the largest span that stays quiet."""
    at_limit = check_broad_service_object(
        "fw1",
        [_rule(BROAD_REF_RULE.replace("tcp-all", "svc-100"))],
        [_svc("svc-100", "8000-8099")],
    )
    over_limit = check_broad_service_object(
        "fw1",
        [_rule(BROAD_REF_RULE.replace("tcp-all", "svc-101"))],
        [_svc("svc-101", "8000-8100")],
    )
    assert at_limit == []
    assert [f.severity for f in over_limit] == ["medium"]


def test_comma_separated_port_list_spans_sum():
    """PAN-OS port values can be lists: '80,443,1000-1200' covers 203 ports."""
    findings = check_broad_service_object(
        "fw1",
        [_rule(BROAD_REF_RULE.replace("tcp-all", "svc-list"))],
        [_svc("svc-list", "80,443,1000-1200")],
    )
    assert len(findings) == 1
    assert "203 ports" in findings[0].detail


def test_broad_object_on_deny_rule_does_not_fire():
    """A deny can be as wide as it likes — width is only risk on allows."""
    rule = _rule(BROAD_REF_RULE.replace("allow", "deny"))
    assert check_broad_service_object("fw1", [rule], [_svc("tcp-all", "0-65535")]) == []


def test_broad_object_on_disabled_rule_does_not_fire():
    rule = _rule(
        BROAD_REF_RULE.replace("<action>allow</action>",
                               "<action>allow</action><disabled>yes</disabled>")
    )
    assert check_broad_service_object("fw1", [rule], [_svc("tcp-all", "0-65535")]) == []


def test_unreferenced_broad_object_does_not_fire():
    """A broad object no enabled allow rule uses passes no traffic — unused
    object hygiene is not rule risk (and not this check)."""
    rule = _rule(
        """<entry name="tight-rule">
             <source><member>branch-lan</member></source>
             <destination><member>web-srv-1</member></destination>
             <service><member>svc-narrow</member></service>
             <application><member>web-browsing</member></application>
             <action>allow</action>
           </entry>"""
    )
    services = [_svc("tcp-all", "0-65535"), _svc("svc-narrow", "8443")]
    assert check_broad_service_object("fw1", [rule], services) == []


def test_predefined_service_reference_does_not_fire():
    """service-http/service-https are predefined — they never appear in the
    config's service section, so a rule pinned to them stays quiet."""
    rule = _rule(BROAD_REF_RULE.replace("tcp-all", "service-https"))
    assert check_broad_service_object("fw1", [rule], []) == []


def test_malformed_port_text_never_fires_or_raises():
    """Unparseable port values count zero — under-reporting a weird value
    beats inventing a finding from it (shadowed-rule's stance)."""
    services = [
        _svc("svc-weird", "high-ports"),
        _svc("svc-empty", ""),
        _svc("svc-backwards", "9000-8000"),
    ]
    rules = [
        _rule(BROAD_REF_RULE.replace("tcp-all", name))
        for name in ("svc-weird", "svc-empty", "svc-backwards")
    ]
    assert check_broad_service_object("fw1", rules, services) == []


def test_rule_service_fields_are_not_picked_up_as_service_objects():
    """The XPath trap: a rule's <service> holds <member> references; a service
    OBJECT is an <entry> under a service section. iter_service_objects must
    return only the latter, or every rule's service field becomes a phantom
    zero-span object."""
    config = f"""<config><devices><entry name="fw"><vsys><entry name="vsys1">
        <service>
          <entry name="tcp-all"><protocol><tcp><port>0-65535</port></tcp></protocol></entry>
        </service>
        <rulebase><security><rules>
          {BROAD_REF_RULE}
        </rules></security></rulebase>
    </entry></vsys></entry></devices></config>"""
    objects = iter_service_objects(config)
    assert [e.get("name") for e in objects] == ["tcp-all"]


def test_broad_service_object_reachable_via_audit_config():
    """audit_config() must hand the check its service objects end-to-end —
    a check invoked explicitly (not via CHECKS) is the easiest one to forget
    to wire."""
    config = f"""<config><devices><entry name="fw"><vsys><entry name="vsys1">
        <service>
          <entry name="tcp-all"><protocol><tcp><port>0-65535</port></tcp></protocol></entry>
        </service>
        <rulebase><security><rules>
          {BROAD_REF_RULE}
        </rules></security></rulebase>
    </entry></vsys></entry></devices></config>"""
    findings = audit_config("fw1", config)
    assert [(f.check, f.severity) for f in findings] == [("broad-service-object", "medium")]
