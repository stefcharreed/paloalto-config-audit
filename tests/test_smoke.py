"""Smoke tests — prove the offline pipeline (no live Panorama/firewall) works
end to end, same shape as netmiko-config-audit's phantom-drift guard.
"""
from panos_audit.collector import fetch_running_config
from panos_audit.drift import compare_to_baseline
from panos_audit.inventory import Device

BASELINE = """<config>
  <rules>
    <entry name="allow-web" uuid="aaaa"><action>allow</action></entry>
  </rules>
</config>"""

# Same rule, different uuid, different whitespace — must NOT show as drift.
CURRENT_NOISE_ONLY = """<config><rules><entry name="allow-web" uuid="bbbb">
<action>allow</action></entry></rules></config>"""

# A real change: action flips from allow to deny.
CURRENT_REAL_DRIFT = """<config>
  <rules>
    <entry name="allow-web" uuid="aaaa"><action>deny</action></entry>
  </rules>
</config>"""


def test_phantom_drift_guard():
    result = compare_to_baseline("fw1", CURRENT_NOISE_ONLY, BASELINE)
    assert result.has_drift is False


def test_real_drift_detected():
    result = compare_to_baseline("fw1", CURRENT_REAL_DRIFT, BASELINE)
    assert result.has_drift is True


def test_collector_offline_seam():
    device = Device(name="fw1", host="192.0.2.1", mode="firewall", api_key="x")
    result = fetch_running_config(device, source_text=BASELINE)
    assert result.ok is True
    assert result.config_text == BASELINE
