"""Tests for the Yahoo Ads module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONSENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_HIGH,
    IMPACT_LOW,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def ya():
    return module_by_id("yahoo_ads")


def test_identity(ya) -> None:
    assert ya.module_id == "yahoo_ads"
    assert ya.module_name == "Yahoo Ads"


@pytest.mark.parametrize(
    "host", ["analytics.yahoo.com", "ads.yahoo.com", "ups.analytics.yahoo.com"],
)
def test_matches(ya, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/ups/12345/cms")
    assert ya.matches(event) is True


def test_does_not_match_bare_yahoo_com(ya) -> None:
    event = make_request(host="yahoo.com", url="https://yahoo.com/")
    assert ya.matches(event) is False


def test_path_extracts_advertiser_id(ya) -> None:
    """``/ups/<digits>/`` paths surface the advertiser ID as a synthetic param."""
    event = make_request(
        host="ups.analytics.yahoo.com",
        url="https://ups.analytics.yahoo.com/ups/9876543/cms",
    )
    hit = ya.parse(event)
    p = next(p for p in hit.params if p.key == "(path) advertiser_id")
    assert p.value == "9876543"
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


def test_hosted_id_is_high_impact(ya) -> None:
    event = make_request(host="ups.analytics.yahoo.com", url="https://ups.analytics.yahoo.com/?_hosted_id=ABC")
    hit = ya.parse(event)
    p = next(p for p in hit.params if p.key == "_hosted_id")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


def test_uid_is_high_impact(ya) -> None:
    event = make_request(host="ups.analytics.yahoo.com", url="https://ups.analytics.yahoo.com/?uid=ABC")
    hit = ya.parse(event)
    p = next(p for p in hit.params if p.key == "uid")
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["partner_id", "advertiser_id"])
def test_identifiers(ya, key: str) -> None:
    event = make_request(host="ups.analytics.yahoo.com", url=f"https://ups.analytics.yahoo.com/?{key}=x")
    hit = ya.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize("key", ["_ev", "redir", "r"])
def test_technical(ya, key: str) -> None:
    event = make_request(host="ups.analytics.yahoo.com", url=f"https://ups.analytics.yahoo.com/?{key}=x")
    hit = ya.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


@pytest.mark.parametrize("key", ["gdpr", "gdpr_consent", "us_privacy"])
def test_consent(ya, key: str) -> None:
    event = make_request(host="ups.analytics.yahoo.com", url=f"https://ups.analytics.yahoo.com/?{key}=1")
    hit = ya.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


def test_unknown_param(ya) -> None:
    event = make_request(host="ups.analytics.yahoo.com", url="https://ups.analytics.yahoo.com/?weird=1")
    hit = ya.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Yahoo Ads" in p.meaning
