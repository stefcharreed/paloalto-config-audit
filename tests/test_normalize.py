"""normalize() property tests — phantom-drift prevention is the whole game."""
import warnings
from pathlib import Path

import pytest

from panos_audit.normalize import normalize

FIXTURES = Path(__file__).parent / "fixtures"


def test_uuid_and_formatting_differences_normalize_identically():
    """The load-bearing property: baseline (pretty, uuid A) and current
    (single-line, uuid B) are the same config and MUST normalize to the same
    lines, or every run reports phantom drift."""
    baseline = (FIXTURES / "fw1_baseline.xml").read_text(encoding="utf-8")
    current = (FIXTURES / "fw1_current_clean.xml").read_text(encoding="utf-8")
    assert normalize(baseline) == normalize(current)


def test_rule_order_is_preserved_not_sorted():
    a = "<rules><entry name='b'/><entry name='a'/></rules>"
    out = normalize(a)
    b_pos = next(i for i, line in enumerate(out) if 'name="b"' in line or "name='b'" in line)
    a_pos = next(i for i, line in enumerate(out) if 'name="a"' in line or "name='a'" in line)
    assert b_pos < a_pos, "rule order must survive normalization — policy is top-down"


def test_values_are_kept():
    out = "\n".join(normalize("<config><action>deny</action></config>"))
    assert "deny" in out


def test_unparseable_input_falls_back_loudly():
    with pytest.warns(UserWarning, match="not parseable XML"):
        out = normalize("this is not xml\n\nat all")
    assert out == ["this is not xml", "at all"]


def test_parseable_input_does_not_warn():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        normalize("<config/>")
