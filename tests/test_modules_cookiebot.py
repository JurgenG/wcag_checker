"""Tests for the Cookiebot CMP module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_LOW,
    IMPACT_MEDIUM,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def cb():
    return module_by_id("cookiebot")


def test_identity(cb) -> None:
    assert cb.module_id == "cookiebot"
    assert cb.module_name == "Cookiebot"
    assert cb.legal_jurisdiction == "DE"
    assert cb.data_residency


@pytest.mark.parametrize(
    "host",
    ["cookiebot.com", "consent.cookiebot.com", "cookiebot.eu", "consent.cookiebot.eu"],
)
def test_matches(cb, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/cc.js")
    assert cb.matches(event) is True


def test_matches_is_case_insensitive(cb) -> None:
    event = make_request(host="CONSENT.COOKIEBOT.COM", url="https://CONSENT.COOKIEBOT.COM/")
    assert cb.matches(event) is True


def test_does_not_match_unrelated(cb) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert cb.matches(event) is False


def test_cbid_is_identifier(cb) -> None:
    event = make_request(
        host="consent.cookiebot.com",
        url="https://consent.cookiebot.com/uc.js?cbid=ABCD-1234",
    )
    hit = cb.parse(event)
    p = next(p for p in hit.params if p.key == "cbid")
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize(
    "key", ["culture", "language", "version", "v", "type", "framework"],
)
def test_other_known_params_are_technical(cb, key: str) -> None:
    event = make_request(
        host="consent.cookiebot.com",
        url=f"https://consent.cookiebot.com/uc.js?{key}=x",
    )
    hit = cb.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param_falls_through(cb) -> None:
    event = make_request(
        host="consent.cookiebot.com",
        url="https://consent.cookiebot.com/uc.js?weird=1",
    )
    hit = cb.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Cookiebot" in p.meaning
    assert p.privacy_impact == IMPACT_LOW
