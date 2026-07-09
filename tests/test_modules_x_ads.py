"""Tests for the X (Twitter) Ads module."""

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
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def xa():
    return module_by_id("x_ads")


def test_identity(xa) -> None:
    assert xa.module_id == "x_ads"
    assert xa.module_name == "X (Twitter) Ads"
    assert xa.vendor == "X Corp."
    assert xa.legal_jurisdiction == "US"


def test_matches_analytics_twitter(xa) -> None:
    event = make_request(
        host="analytics.twitter.com",
        url="https://analytics.twitter.com/i/adsct?p_id=1",
    )
    assert xa.matches(event) is True


def test_does_not_match_t_co(xa) -> None:
    """``t.co`` is the URL shortener, not the conversion pixel."""
    event = make_request(host="t.co", url="https://t.co/abc")
    assert xa.matches(event) is False


def test_does_not_match_platform_twitter(xa) -> None:
    event = make_request(host="platform.twitter.com", url="https://platform.twitter.com/widgets.js")
    assert xa.matches(event) is False


def test_p_user_id_is_pii_high(xa) -> None:
    """``p_user_id`` carries an advertiser-supplied user ID (often a hashed email)."""
    event = make_request(
        host="analytics.twitter.com",
        url="https://analytics.twitter.com/i/adsct?p_user_id=hashed",
    )
    hit = xa.parse(event)
    p = next(p for p in hit.params if p.key == "p_user_id")
    assert p.category == CAT_PII
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["txn_id", "event_id"])
def test_identifiers(xa, key: str) -> None:
    event = make_request(host="analytics.twitter.com", url=f"https://analytics.twitter.com/i/adsct?{key}=1")
    hit = xa.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


@pytest.mark.parametrize("key", ["p_id"])
def test_technical(xa, key: str) -> None:
    event = make_request(host="analytics.twitter.com", url=f"https://analytics.twitter.com/i/adsct?{key}=1")
    hit = xa.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


@pytest.mark.parametrize("key", ["events", "tw_sale_amount", "tw_order_quantity"])
def test_behavioral(xa, key: str) -> None:
    event = make_request(host="analytics.twitter.com", url=f"https://analytics.twitter.com/i/adsct?{key}=1")
    hit = xa.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_BEHAVIORAL


def test_document_href_is_content(xa) -> None:
    event = make_request(host="analytics.twitter.com", url="https://analytics.twitter.com/i/adsct?tw_document_href=https://x")
    hit = xa.parse(event)
    p = next(p for p in hit.params if p.key == "tw_document_href")
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["gdpr", "gdpr_consent"])
def test_consent(xa, key: str) -> None:
    event = make_request(host="analytics.twitter.com", url=f"https://analytics.twitter.com/i/adsct?{key}=1")
    hit = xa.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


def test_unknown_param_falls_through(xa) -> None:
    event = make_request(host="analytics.twitter.com", url="https://analytics.twitter.com/i/adsct?weird=1")
    hit = xa.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "X Ads" in p.meaning
