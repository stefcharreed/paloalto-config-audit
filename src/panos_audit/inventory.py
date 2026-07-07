"""Load tool configuration and merge the API key from the environment.

Device addressing lives in config.yaml (a sanitized example is version-controlled).
The API key lives in secrets.env (gitignored) and is merged in at runtime, so it
never touches the repo. Mirrors netmiko-config-audit's inventory.py.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from dotenv import load_dotenv

# device_group is spliced into an XPath expression by the collector, inside
# single quotes. Validate it here — at load time, before any request is built —
# so a name that would break (or reshape) the query is a config error, not a
# malformed API call. PAN-OS device-group names are alphanumerics, space,
# dot, underscore, hyphen; this allowlist matches that.
_DEVICE_GROUP_RE = re.compile(r"^[A-Za-z0-9._ -]+$")


@dataclass
class Device:
    name: str
    host: str
    mode: str               # "firewall" | "panorama"
    api_key: str
    device_group: str = ""  # required when mode == "panorama"


@dataclass
class Settings:
    backup_dir: Path      # where current configs are written (actual state)
    baseline_dir: Path    # per-device approved configs (intended state)
    report_path: Path


@dataclass
class Config:
    settings: Settings
    devices: list[Device] = field(default_factory=list)


def load_config(config_path: str | Path, secrets_path: str | Path = "secrets.env") -> Config:
    """Read config.yaml + secrets.env into a typed Config object."""
    load_dotenv(secrets_path)
    default_key = os.environ.get("PANOS_API_KEY", "")

    raw = yaml.safe_load(Path(config_path).read_text())
    s = raw.get("settings", {})
    settings = Settings(
        backup_dir=Path(s.get("backup_dir", "../panos-config-backups")),
        baseline_dir=Path(s.get("baseline_dir", "../panos-config-backups/baselines")),
        report_path=Path(s.get("report_path", "../panos-config-backups/reports")),
    )

    devices: list[Device] = []
    for i, d in enumerate(raw.get("devices", [])):
        for required in ("name", "host", "mode"):
            if required not in d:
                label = d.get("name", f"#{i + 1}")
                raise ValueError(
                    f"device {label} in {config_path} is missing required field "
                    f"'{required}'"
                )
        if d["mode"] not in ("firewall", "panorama"):
            raise ValueError(f"device {d['name']}: mode must be 'firewall' or 'panorama'")
        if d["mode"] == "panorama" and not d.get("device_group"):
            raise ValueError(f"device {d['name']}: mode=panorama requires 'device_group'")
        group = d.get("device_group", "")
        if group and not _DEVICE_GROUP_RE.match(group):
            raise ValueError(
                f"device {d['name']}: device_group {group!r} contains characters "
                f"outside [A-Za-z0-9._ -] — it is embedded in an XPath query and "
                f"must not carry quotes/brackets"
            )

        devices.append(
            Device(
                name=d["name"],
                host=d["host"],
                mode=d["mode"],
                api_key=d.get("api_key", default_key),
                device_group=d.get("device_group", ""),
            )
        )
    return Config(settings=settings, devices=devices)
