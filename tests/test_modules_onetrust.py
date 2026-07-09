"""Tests for the OneTrust CMP module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_LOW,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def ot():
    return module_by_id("onetrust")


def test_identity(ot) -> None:
    assert ot.module_id == "onetrust"
    assert ot.module_name == "OneTrust"
    assert ot.legal_jurisdiction == "US"


@pytest.mark.parametrize(
    "host",
    [
        "onetrust.com",
        "cookielaw.org",
        "cookiepro.com",
        "geolocation.onetrust.com",
        "cdn.cookielaw.org",
        "app-eu.onetrust.com",
    ],
)
def test_matches(ot, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert ot.matches(event) is True


def test_does_not_match_unrelated(ot) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert ot.matches(event) is False


def test_domain_data_is_identifier(ot) -> None:
    event = make_request(host="cdn.cookielaw.org", url="https://cdn.cookielaw.org/x?domainData=abc")
    hit = ot.parse(event)
    p = next(p for p in hit.params if p.key == "domainData")
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize(
    "key", ["tcfVersion", "language", "culture", "v", "version", "callback", "country", "state"],
)
def test_technical_params(ot, key: str) -> None:
    event = make_request(host="cdn.cookielaw.org", url=f"https://cdn.cookielaw.org/x?{key}=v")
    hit = ot.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param_falls_through(ot) -> None:
    event = make_request(host="cdn.cookielaw.org", url="https://cdn.cookielaw.org/x?weird=1")
    hit = ot.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "OneTrust" in p.meaning
