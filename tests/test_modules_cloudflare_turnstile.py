"""Tests for the Cloudflare Turnstile module."""

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
def cft():
    return module_by_id("cloudflare_turnstile")


def test_identity(cft) -> None:
    assert cft.module_id == "cloudflare_turnstile"
    assert cft.module_name == "Cloudflare Turnstile"
    assert cft.vendor == "Cloudflare, Inc."
    assert cft.legal_jurisdiction == "US"


def test_matches_challenges_host(cft) -> None:
    event = make_request(
        host="challenges.cloudflare.com",
        url="https://challenges.cloudflare.com/turnstile/v0/api.js",
    )
    assert cft.matches(event) is True


def test_matches_is_case_insensitive(cft) -> None:
    event = make_request(
        host="CHALLENGES.CLOUDFLARE.COM",
        url="https://CHALLENGES.CLOUDFLARE.COM/turnstile/v0/api.js",
    )
    assert cft.matches(event) is True


def test_does_not_match_bare_cloudflare_com(cft) -> None:
    event = make_request(host="cloudflare.com", url="https://cloudflare.com/")
    assert cft.matches(event) is False


@pytest.mark.parametrize(
    ("key", "expected_category", "expected_impact"),
    [
        ("sitekey", CAT_TECHNICAL, IMPACT_LOW),
        ("k", CAT_TECHNICAL, IMPACT_LOW),
        ("c", CAT_IDENTIFIER, IMPACT_MEDIUM),
        ("cid", CAT_IDENTIFIER, IMPACT_MEDIUM),
        ("action", CAT_BEHAVIORAL, IMPACT_LOW),
        ("cdata", CAT_BEHAVIORAL, IMPACT_LOW),
        ("origin", CAT_BEHAVIORAL, IMPACT_LOW),
        ("render", CAT_TECHNICAL, IMPACT_LOW),
        ("theme", CAT_TECHNICAL, IMPACT_LOW),
        ("v", CAT_TECHNICAL, IMPACT_LOW),
    ],
)
def test_classify_known_params(cft, key, expected_category, expected_impact) -> None:
    event = make_request(
        host="challenges.cloudflare.com",
        url=f"https://challenges.cloudflare.com/turnstile/v0/api.js?{key}=x",
    )
    hit = cft.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == expected_category
    assert p.privacy_impact == expected_impact


def test_unknown_param_falls_through(cft) -> None:
    event = make_request(
        host="challenges.cloudflare.com",
        url="https://challenges.cloudflare.com/turnstile/v0/api.js?surprise=1",
    )
    hit = cft.parse(event)
    p = next(p for p in hit.params if p.key == "surprise")
    assert p.category == CAT_OTHER
    assert "Turnstile" in p.meaning
