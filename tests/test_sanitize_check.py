"""Sanitizer tests — the pre-commit gate is only as good as these regexes.

Secret-shaped test strings are constructed at runtime (concatenation) so the
raw bytes of this file never contain the patterns scripts/pre-commit greps
for — otherwise the hook would block committing its own test suite. The
sanitizer still sees the assembled string, which is what's under test.
"""
from pathlib import Path

from panos_audit.sanitize_check import check_config

FIXTURES = Path(__file__).parent / "fixtures"


def _categories(findings: list[dict]) -> set[str]:
    return {f["category"] for f in findings}


def test_every_committed_fixture_is_clean():
    fixture_files = sorted(FIXTURES.glob("*.xml"))
    assert fixture_files, "no fixtures found — the glob is looking in the wrong place"
    for fixture in fixture_files:
        findings = check_config(fixture.read_text(encoding="utf-8"))
        assert findings == [], f"{fixture.name} has unsanitized content: {findings}"


def test_doc_range_ips_pass():
    assert check_config("<ip-netmask>192.0.2.1/32</ip-netmask>") == []
    assert check_config("<ip-netmask>203.0.113.7/32</ip-netmask>") == []


def test_private_ip_flagged():
    findings = check_config("<ip-netmask>10.20.30.40/32</ip-netmask>")
    assert _categories(findings) == {"private_ip"}


def test_public_ip_flagged():
    findings = check_config("<ip-netmask>8.8.8.8/32</ip-netmask>")
    assert _categories(findings) == {"real_ip"}


def test_masks_and_wildcards_not_flagged():
    assert check_config("<netmask>255.255.255.0</netmask>") == []
    assert check_config("<wildcard>0.0.0.255</wildcard>") == []


def test_phash_flagged():
    line = "<pha" + "sh>fakehashvalue</pha" + "sh>"
    findings = check_config(line)
    assert _categories(findings) == {"credential"}


def test_password_element_flagged():
    line = "<pass" + "word>not-a-real-psk</pass" + "word>"
    findings = check_config(line)
    assert _categories(findings) == {"credential"}


def test_api_key_flagged():
    line = "key = " + "LUFRPT" + "0" * 24
    findings = check_config(line)
    assert _categories(findings) == {"credential"}


def test_findings_carry_line_numbers():
    text = "<config>\n<ip-netmask>10.0.0.1/32</ip-netmask>\n</config>"
    findings = check_config(text)
    assert len(findings) == 1
    assert findings[0]["line_number"] == 2
    assert "10.0.0.1" in findings[0]["line"]


def test_invalid_ip_shape_ignored():
    # Looks like an IP but isn't one — must not crash or flag.
    assert check_config("<comment>version 999.1.1.1 notes</comment>") == []
