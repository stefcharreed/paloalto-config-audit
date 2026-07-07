"""Normalize a PAN-OS XML config so a diff fires on real change, not noise.

CRITICAL: normalize() is pure and MUST be applied IDENTICALLY to BOTH sides
(baseline and current) before difflib sees them — same rule as
netmiko-config-audit, and for the same reason: normalizing only one side
manufactures phantom drift.

v1 approach: parse the XML and re-serialize it with consistent indentation and
a stable attribute/child order, so two configs that are semantically identical
but formatted differently (whitespace, attribute order) don't show as drift.

What it strips (extend this list as real noise is observed on a lab firewall —
don't guess ahead of what's actually seen, per the same rule netmiko-config-audit's
normalize.py follows for crypto/PKI blobs):
    - <uuid> attributes (PAN-OS assigns these per-object; they change across
      re-creation of an otherwise-identical rule and aren't operator intent)
What it deliberately KEEPS:
    - rule/object ORDER (security policy is evaluated top-down; a reorder is
      real, meaningful drift — never sort children)
    - every configured value, including anything that looks like a reference
      to a credential object (PAN-OS stores secrets as opaque phash values in
      config XML, not plaintext — see sanitize_check.py for handling those)
"""
from __future__ import annotations

import xml.etree.ElementTree as ET


def _strip_volatile(elem: ET.Element) -> None:
    elem.attrib.pop("uuid", None)
    for child in elem:
        _strip_volatile(child)


def normalize(config_text: str) -> list[str]:
    """Parse `config_text` as XML, strip known-volatile noise, and return a
    stable, line-oriented representation for diffing.

    Falls back to raw non-blank lines if the text isn't parseable XML — this
    keeps the function usable during early development against partial/mocked
    fixtures, but a normalize() that silently no-ops on real device output
    would hide malformed API responses, so this fallback is deliberately loud:
    callers should treat ParseError-triggered fallback as worth investigating,
    not steady-state behavior.
    """
    try:
        root = ET.fromstring(config_text)
    except ET.ParseError:
        return [line.rstrip() for line in config_text.splitlines() if line.strip()]

    _strip_volatile(root)
    canonical = ET.tostring(root, encoding="unicode")
    # Re-parse via minidom for stable, indented output — a consistent
    # formatting pass so pretty-printer differences never show up as drift.
    import xml.dom.minidom as minidom

    pretty = minidom.parseString(canonical).toprettyxml(indent="  ")
    return [line for line in pretty.splitlines() if line.strip()]
