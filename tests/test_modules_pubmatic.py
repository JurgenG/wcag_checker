"""Tests for the PubMatic SSP module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONSENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_LOW,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def pm():
    return module_by_id("pubmatic")


def test_identity(pm) -> None:
    assert pm.module_id == "pubmatic"
    assert pm.module_name == "PubMatic"
    assert pm.legal_jurisdiction == "US"


@pytest.mark.parametrize(
    "host", ["pubmatic.com", "image2.pubmatic.com", "ads.pubmatic.com", "rtb.pubmatic.com"],
)
def test_matches(pm, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/AdServer/Pug")
    assert pm.matches(event) is True


def test_does_not_match_unrelated(pm) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert pm.matches(event) is False


@pytest.mark.parametrize("key", ["vcode", "puid"])
def test_identifiers(pm, key: str) -> None:
    event = make_request(host="image2.pubmatic.com", url=f"https://image2.pubmatic.com/AdServer/Pug?{key}=x")
    hit = pm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


def test_publisher_id_is_technical(pm) -> None:
    """``p`` is the publisher / partner account ID — TECHNICAL / LOW."""
    event = make_request(host="image2.pubmatic.com", url="https://image2.pubmatic.com/AdServer/Pug?p=x")
    hit = pm.parse(event)
    param = next(param for param in hit.params if param.key == "p")
    assert param.category == CAT_TECHNICAL
    assert param.privacy_impact == IMPACT_LOW


def test_predirect_is_technical(pm) -> None:
    event = make_request(host="image2.pubmatic.com", url="https://image2.pubmatic.com/?predirect=https://x")
    hit = pm.parse(event)
    p = next(p for p in hit.params if p.key == "predirect")
    assert p.category == CAT_TECHNICAL


@pytest.mark.parametrize("key", ["gdpr", "gdpr_consent", "us_privacy"])
def test_consent(pm, key: str) -> None:
    event = make_request(host="image2.pubmatic.com", url=f"https://image2.pubmatic.com/?{key}=1")
    hit = pm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


@pytest.mark.parametrize("key", ["nc", "rd", "ts"])
def test_technical(pm, key: str) -> None:
    event = make_request(host="image2.pubmatic.com", url=f"https://image2.pubmatic.com/?{key}=x")
    hit = pm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param_falls_through(pm) -> None:
    event = make_request(host="image2.pubmatic.com", url="https://image2.pubmatic.com/?weird=1")
    hit = pm.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "PubMatic" in p.meaning
