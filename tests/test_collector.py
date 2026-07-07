"""Collector tests — offline seam + query construction. No network, ever."""
from panos_audit.collector import _xpath_for, collect_all, fetch_running_config
from panos_audit.inventory import Device


def _fw(name="fw1"):
    return Device(name=name, host="192.0.2.1", mode="firewall", api_key="k")


def _panorama(name="branch-fw-01"):
    return Device(
        name=name, host="192.0.2.5", mode="panorama", api_key="k",
        device_group="branch-offices",
    )


def test_offline_seam_returns_source_text():
    result = fetch_running_config(_fw(), source_text="<config/>")
    assert result.ok is True
    assert result.config_text == "<config/>"


def test_collect_all_maps_source_texts_by_device_name():
    texts = {"fw1": "<a/>", "fw2": "<b/>"}
    results = collect_all([_fw("fw1"), _fw("fw2")], source_texts=texts)
    assert [(r.device, r.config_text) for r in results] == [("fw1", "<a/>"), ("fw2", "<b/>")]


def test_xpath_direct_firewall_is_whole_config():
    assert _xpath_for(_fw()) == "/config"


def test_xpath_panorama_targets_the_device_group():
    xpath = _xpath_for(_panorama())
    assert "device-group" in xpath
    assert "'branch-offices'" in xpath
