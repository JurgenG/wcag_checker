"""Tests for the Google Tag Manager module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_LOW,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def gtm():
    return module_by_id("googletagmanager")


def test_identity(gtm) -> None:
    assert gtm.module_id == "googletagmanager"
    assert gtm.module_name == "Google Tag Manager"
    assert gtm.vendor == "Google LLC"


@pytest.mark.parametrize(
    "host", ["googletagmanager.com", "www.googletagmanager.com"],
)
def test_matches(gtm, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/gtm.js?id=GTM-XYZ")
    assert gtm.matches(event) is True


def test_does_not_match_unrelated(gtm) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert gtm.matches(event) is False


@pytest.mark.parametrize("key", ["id", "gtm_auth"])
def test_property_ids_are_technical(gtm, key: str) -> None:
    event = make_request(
        host="www.googletagmanager.com",
        url=f"https://www.googletagmanager.com/gtm.js?{key}=x",
    )
    hit = gtm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize(
    "key", ["gtm_preview", "gtm_cookies_win", "l", "cx", "cb", "gtm"],
)
def test_technical(gtm, key: str) -> None:
    event = make_request(
        host="www.googletagmanager.com",
        url=f"https://www.googletagmanager.com/gtm.js?{key}=x",
    )
    hit = gtm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param(gtm) -> None:
    event = make_request(
        host="www.googletagmanager.com",
        url="https://www.googletagmanager.com/gtm.js?weird=1",
    )
    hit = gtm.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "GTM" in p.meaning
