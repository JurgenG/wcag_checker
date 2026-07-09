"""Tests for the Cloudflare Web Analytics module."""

from __future__ import annotations

import json
import urllib.parse

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_LOW,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def cf():
    return module_by_id("cloudflare_web_analytics")


def test_identity(cf) -> None:
    assert cf.module_id == "cloudflare_web_analytics"
    assert cf.module_name == "Cloudflare Web Analytics"


def test_matches_loader_host(cf) -> None:
    event = make_request(
        host="static.cloudflareinsights.com",
        url="https://static.cloudflareinsights.com/beacon.min.js",
    )
    assert cf.matches(event) is True


def test_matches_first_party_relayed_rum_path(cf) -> None:
    """``/cdn-cgi/rum`` on ANY host is claimed — first-party-relayed beacon."""
    event = make_request(
        host="www.example.com",
        url="https://www.example.com/cdn-cgi/rum",
    )
    assert cf.matches(event) is True


def test_does_not_match_unrelated(cf) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert cf.matches(event) is False


@pytest.mark.parametrize("key", ["token", "t"])
def test_token_is_technical_low(cf, key: str) -> None:
    event = make_request(
        host="static.cloudflareinsights.com",
        url=f"https://static.cloudflareinsights.com/beacon.min.js?{key}=ABC",
    )
    hit = cf.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


def test_b_is_behavioral(cf) -> None:
    event = make_request(
        host="static.cloudflareinsights.com",
        url="https://static.cloudflareinsights.com/cdn-cgi/rum?b=1",
    )
    hit = cf.parse(event)
    p = next(p for p in hit.params if p.key == "b")
    assert p.category == CAT_BEHAVIORAL


@pytest.mark.parametrize("key", ["url", "referrer"])
def test_content(cf, key: str) -> None:
    event = make_request(
        host="static.cloudflareinsights.com",
        url=f"https://static.cloudflareinsights.com/cdn-cgi/rum?{key}=x",
    )
    hit = cf.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["bv", "si", "rv"])
def test_technical(cf, key: str) -> None:
    event = make_request(
        host="static.cloudflareinsights.com",
        url=f"https://static.cloudflareinsights.com/cdn-cgi/rum?{key}=x",
    )
    hit = cf.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_data_blob_extracts_site_id_and_pages(cf) -> None:
    """The ``data`` field carries URL-encoded JSON with site ID + page list."""
    blob = json.dumps({
        "si": "SITE123",
        "li": [{"u": "https://example.com/article"}, {"u": "https://example.com/other"}],
    })
    url = (
        "https://www.example.com/cdn-cgi/rum?data="
        + urllib.parse.quote(blob)
    )
    event = make_request(host="www.example.com", url=url)
    hit = cf.parse(event)
    by_key = {p.key: p for p in hit.params}
    assert by_key["(body) data.site_id"].value == "SITE123"
    assert by_key["(body) data.site_id"].category == CAT_TECHNICAL
    assert by_key["(body) data.site_id"].privacy_impact == IMPACT_LOW
    assert by_key["(body) data.page_count"].value == "2"
    assert by_key["(body) data.first_page_url"].value == "https://example.com/article"


def test_data_blob_handles_invalid_json(cf) -> None:
    event = make_request(
        host="www.example.com",
        url="https://www.example.com/cdn-cgi/rum?data=not-json",
    )
    hit = cf.parse(event)
    # No extracted body params, but the raw 'data' param is still surfaced.
    assert any(p.key == "data" for p in hit.params)
    assert not any(p.key.startswith("(body) data.") for p in hit.params)


def test_unknown_param(cf) -> None:
    event = make_request(
        host="static.cloudflareinsights.com",
        url="https://static.cloudflareinsights.com/?weird=1",
    )
    hit = cf.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Cloudflare Web Analytics" in p.meaning
