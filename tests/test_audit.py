"""Rulebase audit checks against the committed fixtures.

The drift fixture doubles as the audit's true-positive case: its
temp-emergency-access rule is a literal any/any/any/any allow. The baseline
fixture is the true-negative case — its any/any rule is the deny-all cleanup
rule, which must NOT fire the permissive check.
"""
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from panos_audit.audit import (
    Finding,
    audit_config,
    check_logging_disabled,
    check_overly_permissive,
    iter_security_rules,
)

FIXTURES = Path(__file__).parent / "fixtures"
BASELINE = (FIXTURES / "fw1_baseline.xml").read_text(encoding="utf-8")
DRIFTED = (FIXTURES / "fw1_current_drift.xml").read_text(encoding="utf-8")


def test_clean_rulebase_yields_no_findings():
    assert audit_config("fw1", BASELINE) == []


def test_any_any_allow_is_flagged_high():
    findings = audit_config("fw1", DRIFTED)
    assert len(findings) == 1
    f = findings[0]
    assert f.check == "overly-permissive-rule"
    assert f.rule == "temp-emergency-access"
    assert f.severity == "high"  # service AND application are also any


def test_any_any_deny_does_not_fire():
    """The cleanup rule at the bottom of every rulebase is any/any deny —
    flagging it would bury real findings in noise on every single device."""
    rules = iter_security_rules(BASELINE)
    deny_all = [r for r in rules if r.get("name") == "deny-all"]
    assert deny_all, "fixture must contain the deny-all cleanup rule"
    assert check_overly_permissive("fw1", deny_all) == []


def test_scoped_service_downgrades_to_medium():
    rule = ET.fromstring(
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
    rule = ET.fromstring(
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


# --- logging-disabled (SCAFFOLD: these define the contract; implement
# check_logging_disabled per AUDIT-CHECKS.md, register it in CHECKS, then
# delete the skip marker and make them pass) --------------------------------

logging_scaffold = pytest.mark.skip(
    reason="scaffold — implement check_logging_disabled, then remove this marker"
)


def _rule(xml: str) -> ET.Element:
    return ET.fromstring(xml)


@logging_scaffold
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


@logging_scaffold
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


@logging_scaffold
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


@logging_scaffold
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


@logging_scaffold
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
