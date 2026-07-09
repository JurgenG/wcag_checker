"""Tests for the Google Ads / DoubleClick module."""

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
    IMPACT_MEDIUM,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def ga():
    return module_by_id("google_ads")


def test_identity(ga) -> None:
    assert ga.module_id == "google_ads"
    assert ga.module_name == "Google Ads / DoubleClick"


@pytest.mark.parametrize(
    "host",
    [
        "doubleclick.net", "googleads.g.doubleclick.net",
        "googleadservices.com", "www.googleadservices.com",
        "googletagservices.com", "googlesyndication.com", "pagead2.googlesyndication.com",
        "s0.2mdn.net", "ad-delivery.net", "ep1.adtrafficquality.google",
    ],
)
def test_matches_host_families(ga, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert ga.matches(event) is True


def test_matches_www_google_with_pagead_path(ga) -> None:
    event = make_request(host="www.google.com", url="https://www.google.com/pagead/1p-user-list/123")
    assert ga.matches(event) is True


def test_matches_adservice_floodlight(ga) -> None:
    """adservice.google.com serves DoubleClick Floodlight (/ddm/fls/) tags."""
    event = make_request(
        host="adservice.google.com",
        url="https://adservice.google.com/ddm/fls/z/src=13662078;type=hp;cat=allpages;ord=1",
    )
    assert ga.matches(event) is True


def test_adservice_routes_to_google_ads_via_detect() -> None:
    """No earlier-registered module shadows adservice.google.com."""
    from leak_inspector.modules.base import detect
    event = make_request(
        host="adservice.google.com",
        url="https://adservice.google.com/ddm/fls/z/src=1;type=pagev0;cat=pagev0",
    )
    found = detect(event)
    assert found is not None
    assert found.module_id == "google_ads"


def test_does_not_match_www_google_search_path(ga) -> None:
    event = make_request(host="www.google.com", url="https://www.google.com/search?q=x")
    assert ga.matches(event) is False


def test_auid_is_high_impact(ga) -> None:
    event = make_request(host="googleads.g.doubleclick.net", url="https://googleads.g.doubleclick.net/?auid=ABC")
    hit = ga.parse(event)
    p = next(p for p in hit.params if p.key == "auid")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("value", ["ON", "on", "OFF", "0", "1", "true", "false"])
def test_guid_binary_flag_is_low_technical(ga, value: str) -> None:
    """``guid=ON`` (Floodlight directive) is a setting, not a visitor identifier."""
    event = make_request(
        host="www.google.be",
        url=f"https://www.google.be/pagead/1p-user-list/123/?guid={value}",
    )
    hit = ga.parse(event)
    p = next(p for p in hit.params if p.key == "guid")
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize("value", ["CAESEABC123def", "550e8400-e29b-41d4-a716-446655440000", "abcdef0123456789"])
def test_guid_real_value_is_high_identifier(ga, value: str) -> None:
    """A non-flag ``guid`` value is treated as an actual visitor identifier."""
    event = make_request(
        host="googleads.g.doubleclick.net",
        url=f"https://googleads.g.doubleclick.net/?guid={value}",
    )
    hit = ga.parse(event)
    p = next(p for p in hit.params if p.key == "guid")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


def test_tt_authuser_is_pii(ga) -> None:
    """``tt_authuser`` reveals a signed-in Google account index."""
    event = make_request(host="googleads.g.doubleclick.net", url="https://googleads.g.doubleclick.net/?tt_authuser=0")
    hit = ga.parse(event)
    p = next(p for p in hit.params if p.key == "tt_authuser")
    assert p.category == CAT_PII


def test_uid_is_pii(ga) -> None:
    event = make_request(host="googleads.g.doubleclick.net", url="https://googleads.g.doubleclick.net/?uid=user")
    hit = ga.parse(event)
    p = next(p for p in hit.params if p.key == "uid")
    assert p.category == CAT_PII


@pytest.mark.parametrize("key", ["correlator", "guid"])
def test_identifiers(ga, key: str) -> None:
    event = make_request(host="googleads.g.doubleclick.net", url=f"https://googleads.g.doubleclick.net/?{key}=x")
    hit = ga.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


@pytest.mark.parametrize("key", ["id", "tid", "label", "ai", "tids"])
def test_property_ids_are_technical(ga, key: str) -> None:
    event = make_request(host="googleads.g.doubleclick.net", url=f"https://googleads.g.doubleclick.net/?{key}=x")
    hit = ga.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize("key", ["is_vtc", "value", "currency_code", "transaction_id", "en"])
def test_behavioral(ga, key: str) -> None:
    event = make_request(host="googleads.g.doubleclick.net", url=f"https://googleads.g.doubleclick.net/?{key}=x")
    hit = ga.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_BEHAVIORAL


@pytest.mark.parametrize("key", ["url", "ref", "dl", "dr", "iu"])
def test_content(ga, key: str) -> None:
    event = make_request(host="googleads.g.doubleclick.net", url=f"https://googleads.g.doubleclick.net/?{key}=x")
    hit = ga.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["u_h", "u_w", "u_cd", "u_his", "u_tz"])
def test_fingerprint_surface_technical(ga, key: str) -> None:
    event = make_request(host="googleads.g.doubleclick.net", url=f"https://googleads.g.doubleclick.net/?{key}=x")
    hit = ga.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


@pytest.mark.parametrize("key", ["aip", "gcs", "gcd", "gcu", "npa", "dma", "ct_cookie_present"])
def test_consent(ga, key: str) -> None:
    event = make_request(host="googleads.g.doubleclick.net", url=f"https://googleads.g.doubleclick.net/?{key}=1")
    hit = ga.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


def test_ep_prefix(ga) -> None:
    event = make_request(host="googleads.g.doubleclick.net", url="https://googleads.g.doubleclick.net/?ep.foo=value")
    hit = ga.parse(event)
    p = next(p for p in hit.params if p.key == "ep.foo")
    assert p.category == CAT_BEHAVIORAL
    assert p.privacy_impact == IMPACT_MEDIUM
    assert "foo" in p.meaning


def test_epn_prefix(ga) -> None:
    event = make_request(host="googleads.g.doubleclick.net", url="https://googleads.g.doubleclick.net/?epn.bar=42")
    hit = ga.parse(event)
    p = next(p for p in hit.params if p.key == "epn.bar")
    assert p.category == CAT_BEHAVIORAL
    assert "bar" in p.meaning


def test_unknown_param(ga) -> None:
    event = make_request(host="googleads.g.doubleclick.net", url="https://googleads.g.doubleclick.net/?weirdo=1")
    hit = ga.parse(event)
    p = next(p for p in hit.params if p.key == "weirdo")
    assert p.category == CAT_OTHER
    assert "Google Ads" in p.meaning
