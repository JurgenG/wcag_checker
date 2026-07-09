"""Tests for the LinkedIn Insight Tag module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_PII,
    CAT_TECHNICAL,
    IMPACT_HIGH,
    IMPACT_LOW,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def li():
    return module_by_id("linkedin_insight")


def test_identity(li) -> None:
    assert li.module_id == "linkedin_insight"
    assert li.module_name == "LinkedIn Insight Tag"


@pytest.mark.parametrize("host", ["px.ads.linkedin.com", "snap.licdn.com"])
def test_matches_pixel_and_loader_hosts(li, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert li.matches(event) is True


def test_matches_li_track_on_linkedin_com(li) -> None:
    event = make_request(host="www.linkedin.com", url="https://www.linkedin.com/li/track?pid=1")
    assert li.matches(event) is True


def test_does_not_match_other_linkedin_paths(li) -> None:
    """``linkedin.com`` is only claimed for ``/li/`` tracking paths."""
    event = make_request(host="www.linkedin.com", url="https://www.linkedin.com/feed")
    assert li.matches(event) is False


def test_liUuid_is_high_impact(li) -> None:
    event = make_request(host="px.ads.linkedin.com", url="https://px.ads.linkedin.com/?liUuid=ABC")
    hit = li.parse(event)
    p = next(p for p in hit.params if p.key == "liUuid")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


def test_mid_is_pii_high(li) -> None:
    """``mid`` is set when the visitor is signed into LinkedIn — PII."""
    event = make_request(host="px.ads.linkedin.com", url="https://px.ads.linkedin.com/?mid=123")
    hit = li.parse(event)
    p = next(p for p in hit.params if p.key == "mid")
    assert p.category == CAT_PII
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["liUuidHashed"])
def test_identifiers(li, key: str) -> None:
    event = make_request(host="px.ads.linkedin.com", url=f"https://px.ads.linkedin.com/?{key}=x")
    hit = li.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


@pytest.mark.parametrize("key", ["pid", "liS_pid"])
def test_property_ids_are_technical(li, key: str) -> None:
    event = make_request(host="px.ads.linkedin.com", url=f"https://px.ads.linkedin.com/?{key}=x")
    hit = li.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize("key", ["e", "conversionId"])
def test_behavioral(li, key: str) -> None:
    event = make_request(host="px.ads.linkedin.com", url=f"https://px.ads.linkedin.com/?{key}=x")
    hit = li.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_BEHAVIORAL


@pytest.mark.parametrize("key", ["url", "referrer"])
def test_content(li, key: str) -> None:
    event = make_request(host="px.ads.linkedin.com", url=f"https://px.ads.linkedin.com/?{key}=x")
    hit = li.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["gdprApplies", "gdprConsent"])
def test_consent(li, key: str) -> None:
    event = make_request(host="px.ads.linkedin.com", url=f"https://px.ads.linkedin.com/?{key}=1")
    hit = li.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


@pytest.mark.parametrize("key", ["fmt", "time", "gen", "v"])
def test_technical(li, key: str) -> None:
    event = make_request(host="px.ads.linkedin.com", url=f"https://px.ads.linkedin.com/?{key}=x")
    hit = li.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param(li) -> None:
    event = make_request(host="px.ads.linkedin.com", url="https://px.ads.linkedin.com/?weird=1")
    hit = li.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "LinkedIn" in p.meaning
