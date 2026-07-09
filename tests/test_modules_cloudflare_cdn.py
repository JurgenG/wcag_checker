"""Tests for the Cloudflare CDN (cdnjs) asset module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER

from tests.conftest import make_request, module_by_id


@pytest.fixture
def cf():
    return module_by_id("cloudflare_cdn")


def test_identity(cf) -> None:
    assert cf.module_id == "cloudflare_cdn"
    # US-operated asset CDN — drives the sovereignty + privacy malus via the
    # resilience exposure tally and the privacy module-count deduction.
    assert cf.legal_jurisdiction == "US"


def test_matches_cdnjs(cf) -> None:
    url = "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"
    event = make_request(host="cdnjs.cloudflare.com", url=url)
    assert cf.matches(event) is True


def test_does_not_match_other_cloudflare_products(cf) -> None:
    """Scope is the cdnjs asset CDN only — Cloudflare's analytics / turnstile /
    zaraz hosts have their own modules and must not be swept up here."""
    for host in ("cloudflareinsights.com", "challenges.cloudflare.com",
                 "www.cloudflare.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert cf.matches(event) is False


def test_does_not_match_unrelated(cf) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert cf.matches(event) is False


def test_params_are_asset_fetch_low_impact(cf) -> None:
    event = make_request(
        host="cdnjs.cloudflare.com",
        url="https://cdnjs.cloudflare.com/ajax/libs/x/1.0/x.js?v=2",
    )
    hit = cf.parse(event)
    p = next(p for p in hit.params if p.key == "v")
    assert p.category == CAT_OTHER
