"""Tests for the Google Fonts tracker module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONTENT,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def gf():
    return module_by_id("google_fonts")


def test_identity(gf) -> None:
    assert gf.module_id == "google_fonts"
    assert gf.module_name == "Google Fonts"
    assert gf.vendor == "Google LLC"
    assert gf.legal_jurisdiction == "US"
    assert gf.data_residency
    assert gf.sovereignty_notes


@pytest.mark.parametrize("host", ["fonts.googleapis.com", "fonts.gstatic.com"])
def test_matches_known_hosts(gf, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/css?family=Roboto")
    assert gf.matches(event) is True


def test_matches_is_case_insensitive(gf) -> None:
    event = make_request(
        host="FONTS.GOOGLEAPIS.COM",
        url="https://FONTS.GOOGLEAPIS.COM/css?family=Roboto",
    )
    assert gf.matches(event) is True


def test_does_not_match_unrelated_subdomain(gf) -> None:
    """Only the two specific hosts — not arbitrary *.googleapis.com."""
    event = make_request(
        host="storage.googleapis.com",
        url="https://storage.googleapis.com/x",
    )
    assert gf.matches(event) is False


def test_parse_hit_metadata(gf) -> None:
    event = make_request(
        host="fonts.googleapis.com",
        url="https://fonts.googleapis.com/css?family=Roboto",
        event_id=11,
    )
    hit = gf.parse(event)
    assert isinstance(hit, Hit)
    assert hit.module_id == "google_fonts"
    assert hit.module_name == "Google Fonts"
    assert hit.events == [11]


@pytest.mark.parametrize(
    ("key", "expected_category", "expected_impact"),
    [
        ("family", CAT_CONTENT, IMPACT_MEDIUM),
        ("display", CAT_TECHNICAL, IMPACT_LOW),
        ("subset", CAT_TECHNICAL, IMPACT_LOW),
        ("text", CAT_CONTENT, IMPACT_HIGH),
        ("effect", CAT_TECHNICAL, IMPACT_LOW),
        ("lang", CAT_TECHNICAL, IMPACT_LOW),
    ],
)
def test_classify_known_params(
    gf, key: str, expected_category: str, expected_impact: str,
) -> None:
    event = make_request(
        host="fonts.googleapis.com",
        url=f"https://fonts.googleapis.com/css?{key}=value",
    )
    hit = gf.parse(event)
    param = next(p for p in hit.params if p.key == key)
    assert param.category == expected_category
    assert param.privacy_impact == expected_impact


def test_classify_unknown_param_falls_through(gf) -> None:
    event = make_request(
        host="fonts.googleapis.com",
        url="https://fonts.googleapis.com/css?weirdo=1",
    )
    hit = gf.parse(event)
    param = next(p for p in hit.params if p.key == "weirdo")
    assert param.category == CAT_OTHER
    assert param.privacy_impact == IMPACT_LOW
    assert "Google Fonts" in param.meaning
