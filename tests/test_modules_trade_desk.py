"""Tests for The Trade Desk module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_HIGH,
    IMPACT_LOW,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def ttd():
    return module_by_id("trade_desk")


def test_identity(ttd) -> None:
    assert ttd.module_id == "trade_desk"
    assert ttd.module_name == "The Trade Desk"


@pytest.mark.parametrize("host", ["adsrvr.org", "match.adsrvr.org", "insight.adsrvr.org"])
def test_matches(ttd, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/track/cmf/generic")
    assert ttd.matches(event) is True


def test_does_not_match_unrelated(ttd) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert ttd.matches(event) is False


def test_vrid_is_high_impact(ttd) -> None:
    event = make_request(host="match.adsrvr.org", url="https://match.adsrvr.org/?vrid=ABC")
    hit = ttd.parse(event)
    p = next(p for p in hit.params if p.key == "vrid")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


def test_uid_is_high_impact(ttd) -> None:
    event = make_request(host="match.adsrvr.org", url="https://match.adsrvr.org/?uid=X")
    hit = ttd.parse(event)
    p = next(p for p in hit.params if p.key == "uid")
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["ttd_pid", "adv"])
def test_identifiers(ttd, key: str) -> None:
    event = make_request(host="match.adsrvr.org", url=f"https://match.adsrvr.org/?{key}=x")
    hit = ttd.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize("key", ["ev", "n", "td1", "td2", "td5"])
def test_behavioral(ttd, key: str) -> None:
    event = make_request(host="match.adsrvr.org", url=f"https://match.adsrvr.org/?{key}=x")
    hit = ttd.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_BEHAVIORAL


@pytest.mark.parametrize("key", ["domain", "r"])
def test_content(ttd, key: str) -> None:
    event = make_request(host="match.adsrvr.org", url=f"https://match.adsrvr.org/?{key}=x")
    hit = ttd.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["gdpr", "gdpr_consent", "us_privacy"])
def test_consent(ttd, key: str) -> None:
    event = make_request(host="match.adsrvr.org", url=f"https://match.adsrvr.org/?{key}=1")
    hit = ttd.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


@pytest.mark.parametrize("key", ["v", "nh"])
def test_technical(ttd, key: str) -> None:
    event = make_request(host="match.adsrvr.org", url=f"https://match.adsrvr.org/?{key}=x")
    hit = ttd.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param(ttd) -> None:
    event = make_request(host="match.adsrvr.org", url="https://match.adsrvr.org/?weird=1")
    hit = ttd.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Trade Desk" in p.meaning
