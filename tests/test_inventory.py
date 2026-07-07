"""Inventory loading + validation — every error path exists to fail before a
single API request is built, so each one gets a test."""
import pytest

from panos_audit.inventory import load_config

GOOD = """\
settings:
  backup_dir: "{tmp}/backups"
  baseline_dir: "{tmp}/baselines"
  report_path: "{tmp}/reports"
devices:
  - name: edge-fw
    host: 192.0.2.10
    mode: firewall
  - name: branch-fw-01
    host: 192.0.2.5
    mode: panorama
    device_group: branch-offices
"""


def _write(tmp_path, text: str):
    path = tmp_path / "config.yaml"
    path.write_text(text.format(tmp=tmp_path))
    return path


def _no_secrets(tmp_path):
    return tmp_path / "no-such.env"


def test_loads_valid_config(tmp_path, monkeypatch):
    monkeypatch.setenv("PANOS_API_KEY", "test-key-from-env")
    cfg = load_config(_write(tmp_path, GOOD), secrets_path=_no_secrets(tmp_path))
    assert [d.name for d in cfg.devices] == ["edge-fw", "branch-fw-01"]
    assert cfg.devices[0].api_key == "test-key-from-env"
    assert cfg.devices[1].device_group == "branch-offices"


def test_per_device_api_key_overrides_default(tmp_path, monkeypatch):
    monkeypatch.setenv("PANOS_API_KEY", "default-key")
    text = GOOD.replace("mode: firewall", "mode: firewall\n    api_key: per-device-key")
    cfg = load_config(_write(tmp_path, text), secrets_path=_no_secrets(tmp_path))
    assert cfg.devices[0].api_key == "per-device-key"
    assert cfg.devices[1].api_key == "default-key"


def test_missing_required_field_rejected(tmp_path):
    bad = GOOD.replace("    host: 192.0.2.10\n", "")
    with pytest.raises(ValueError, match="host"):
        load_config(_write(tmp_path, bad), secrets_path=_no_secrets(tmp_path))


def test_bad_mode_rejected(tmp_path):
    bad = GOOD.replace("mode: firewall", "mode: telnet")
    with pytest.raises(ValueError, match="mode"):
        load_config(_write(tmp_path, bad), secrets_path=_no_secrets(tmp_path))


def test_panorama_without_device_group_rejected(tmp_path):
    bad = GOOD.replace("    device_group: branch-offices\n", "")
    with pytest.raises(ValueError, match="device_group"):
        load_config(_write(tmp_path, bad), secrets_path=_no_secrets(tmp_path))


def test_xpath_breaking_device_group_rejected(tmp_path):
    """device_group is embedded in an XPath — a quote in the name must be a
    config error at load time, never a malformed API query at run time."""
    bad = GOOD.replace("device_group: branch-offices", "device_group: \"bad'group\"")
    with pytest.raises(ValueError, match="XPath"):
        load_config(_write(tmp_path, bad), secrets_path=_no_secrets(tmp_path))
