"""Tests for the Cookie Script CMP module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_MEDIUM,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def cs():
    return module_by_id("cookie_script")


def test_identity(cs) -> None:
    assert cs.module_id == "cookie_script"
    assert cs.module_name == "Cookie Script"
    assert cs.legal_jurisdiction == "LT"


@pytest.mark.parametrize(
    "host", ["cookie-script.com", "cdn.cookie-script.com", "consent.cookie-script.com"],
)
def test_matches(cs, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert cs.matches(event) is True


def test_does_not_match_unrelated(cs) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert cs.matches(event) is False


@pytest.mark.parametrize(
    ("key", "expected_category"),
    [
        ("lang", CAT_TECHNICAL),
        ("language", CAT_TECHNICAL),
        ("v", CAT_TECHNICAL),
        ("action", CAT_BEHAVIORAL),
        ("category", CAT_CONSENT),
        ("consenttext", CAT_CONSENT),
        ("dnt", CAT_CONSENT),
        ("page", CAT_CONTENT),
        ("time", CAT_TECHNICAL),
        ("script", CAT_TECHNICAL),
    ],
)
def test_classify_known_params(cs, key: str, expected_category: str) -> None:
    event = make_request(
        host="consent.cookie-script.com",
        url=f"https://consent.cookie-script.com/x?{key}=v",
    )
    hit = cs.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == expected_category


def test_action_is_medium_impact(cs) -> None:
    """``action`` (accept/deny/customize) is the most useful behavioral signal."""
    event = make_request(
        host="consent.cookie-script.com",
        url="https://consent.cookie-script.com/x?action=accept",
    )
    hit = cs.parse(event)
    p = next(p for p in hit.params if p.key == "action")
    assert p.privacy_impact == IMPACT_MEDIUM


def test_unknown_param_falls_through(cs) -> None:
    event = make_request(
        host="cdn.cookie-script.com",
        url="https://cdn.cookie-script.com/x?weird=1",
    )
    hit = cs.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Cookie Script" in p.meaning
