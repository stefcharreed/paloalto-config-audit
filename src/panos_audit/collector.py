"""Collector: pull the running config from PAN-OS/Panorama over the XML API.

Collection ONLY — no hashing, diffing, storage, or git. Per-device try/except
so one unreachable firewall can't kill the whole run. Mirrors the seam in
netmiko-config-audit's collector.py.

Offline seam: pass source_text (or a {name: text} map to collect_all) to develop
and unit-test the pipeline against saved config dumps, with no live device.

PAN-OS API notes (verify against your platform's version before relying on this):
  - Direct firewall: GET https://<host>/api/?type=config&action=show&xpath=/config
    &key=<api_key>
  - Through Panorama, for a device group's pushed config: xpath targets
    /config/devices/entry/device-group/entry[@name='<device_group>']
  - Get a key once via: /api/?type=keygen&user=<u>&password=<p>, then use that
    key going forward — never re-derive it from a stored password at runtime.
  - Panorama and firewalls typically run self-signed certs; verify=False is a
    lab-only shortcut — pin the real cert (or an internal CA bundle) before
    pointing this at anything you care about.
"""
from __future__ import annotations

from dataclasses import dataclass

from .inventory import Device

_TIMEOUT = 30  # seconds — cap every request so a hung device can't hang the run


@dataclass
class CollectionResult:
    device: str
    ok: bool
    config_text: str = ""
    error: str = ""


def _xpath_for(device: Device) -> str:
    if device.mode == "panorama":
        return (
            "/config/devices/entry/device-group/entry"
            f"[@name='{device.device_group}']"
        )
    return "/config"


def fetch_running_config(device: Device, source_text: str | None = None) -> CollectionResult:
    """Fetch one device's config (as raw XML text) wrapped in a result.

    If source_text is given, use it (offline path) instead of calling the API —
    same pattern as netmiko-config-audit, so this whole pipeline is unit-testable
    against saved XML dumps with no live firewall or Panorama.
    """
    if source_text is not None:
        return CollectionResult(device=device.name, ok=True, config_text=source_text)

    # --- LIVE PATH ---------------------------------------------------------
    # requests is imported lazily so the offline path stays importable/testable
    # in environments that never touch the network.
    import requests

    params = {
        "type": "config",
        "action": "show",
        "xpath": _xpath_for(device),
        "key": device.api_key,
    }
    try:
        resp = requests.get(
            f"https://{device.host}/api/",
            params=params,
            timeout=_TIMEOUT,
            verify=False,  # TODO: pin real cert/CA bundle before use outside a lab
        )
        resp.raise_for_status()
        if "<response status=" in resp.text and 'status="success"' not in resp.text:
            return CollectionResult(
                device=device.name, ok=False,
                error=f"PAN-OS API returned non-success: {resp.text[:300]}",
            )
        return CollectionResult(device=device.name, ok=True, config_text=resp.text)
    except Exception as exc:
        # Deliberately broad, same rationale as netmiko-config-audit: one
        # unreachable device must not abort the whole run.
        return CollectionResult(device=device.name, ok=False, error=str(exc))


def collect_all(devices: list[Device], source_texts: dict[str, str] | None = None
                 ) -> list[CollectionResult]:
    """Collect every device, one try/except at a time. Order matches `devices`."""
    source_texts = source_texts or {}
    return [
        fetch_running_config(d, source_text=source_texts.get(d.name))
        for d in devices
    ]
