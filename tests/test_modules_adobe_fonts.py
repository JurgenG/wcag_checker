"""Tests for the Adobe Fonts (Typekit) module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_LOW,
    IMPACT_MEDIUM,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def af():
    return module_by_id("adobe_fonts")


def test_identity(af) -> None:
    assert af.module_id == "adobe_fonts"
    assert af.module_name == "Adobe Fonts (Typekit)"
    assert af.vendor == "Adobe Inc."
    assert af.legal_jurisdiction == "US"
    assert af.data_residency
    assert af.sovereignty_notes


@pytest.mark.parametrize("host", ["p.typekit.net", "use.typekit.net"])
def test_matches_typekit_hosts(af, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/abc.css")
    assert af.matches(event) is True


def test_matches_is_case_insensitive(af) -> None:
    event = make_request(host="P.TYPEKIT.NET", url="https://P.TYPEKIT.NET/k.css")
    assert af.matches(event) is True


def test_does_not_match_lookalike(af) -> None:
    """Only specific subdomains — bare ``typekit.net`` is not claimed."""
    event = make_request(host="typekit.net", url="https://typekit.net/")
    assert af.matches(event) is False


@pytest.mark.parametrize(
    ("key", "expected_category", "expected_impact"),
    [
        ("k", CAT_TECHNICAL, IMPACT_LOW),
        ("a", CAT_TECHNICAL, IMPACT_LOW),
        ("f", CAT_CONTENT, IMPACT_LOW),
        ("s", CAT_TECHNICAL, IMPACT_LOW),
        ("ht", CAT_TECHNICAL, IMPACT_LOW),
        ("app", CAT_TECHNICAL, IMPACT_LOW),
        ("v", CAT_TECHNICAL, IMPACT_LOW),
    ],
)
def test_classify_known_params(af, key, expected_category, expected_impact) -> None:
    event = make_request(host="p.typekit.net", url=f"https://p.typekit.net/css?{key}=x")
    hit = af.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == expected_category
    assert p.privacy_impact == expected_impact


def test_classify_unknown_param(af) -> None:
    event = make_request(host="p.typekit.net", url="https://p.typekit.net/css?weird=1")
    hit = af.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Adobe Fonts" in p.meaning
