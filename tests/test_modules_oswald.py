"""Tests for the Oswald.ai module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_LOW,
    IMPACT_MEDIUM,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def os_():
    return module_by_id("oswald")


def test_identity(os_) -> None:
    assert os_.module_id == "oswald"
    assert os_.module_name == "Oswald.ai"
    assert os_.legal_jurisdiction == "BE"  # EU vendor — important sovereignty marker


@pytest.mark.parametrize(
    "host",
    ["oswald.ai", "widget.oswald.ai", "api.oswald.ai"],
)
def test_matches_apex_and_subdomains(os_, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert os_.matches(event) is True


def test_matches_is_case_insensitive(os_) -> None:
    event = make_request(host="WIDGET.OSWALD.AI", url="https://WIDGET.OSWALD.AI/x")
    assert os_.matches(event) is True


def test_does_not_match_unrelated(os_) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert os_.matches(event) is False


@pytest.mark.parametrize(
    ("key", "expected_category", "expected_impact"),
    [
        ("token", CAT_TECHNICAL, IMPACT_LOW),
        ("session", CAT_IDENTIFIER, IMPACT_MEDIUM),
        ("sessionId", CAT_IDENTIFIER, IMPACT_MEDIUM),
        ("open", CAT_BEHAVIORAL, IMPACT_LOW),
        ("locale", CAT_TECHNICAL, IMPACT_LOW),
        ("env", CAT_TECHNICAL, IMPACT_LOW),
    ],
)
def test_classify_known_params(os_, key, expected_category, expected_impact) -> None:
    event = make_request(host="widget.oswald.ai", url=f"https://widget.oswald.ai/bubble?{key}=x")
    hit = os_.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == expected_category
    assert p.privacy_impact == expected_impact


def test_unknown_param_falls_through(os_) -> None:
    event = make_request(host="widget.oswald.ai", url="https://widget.oswald.ai/bubble?surprise=1")
    hit = os_.parse(event)
    p = next(p for p in hit.params if p.key == "surprise")
    assert p.category == CAT_OTHER
    assert "Oswald" in p.meaning
