"""Tests for the Microsoft Bing UET module."""

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
def uet():
    return module_by_id("bing_uet")


def test_identity(uet) -> None:
    assert uet.module_id == "bing_uet"
    assert uet.module_name == "Microsoft Bing UET"
    assert uet.legal_jurisdiction == "US"


@pytest.mark.parametrize("host", ["bat.bing.com", "bat.bing.net", "bat.r.msn.com", "c.bing.com"])
def test_matches(uet, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/bat.js")
    assert uet.matches(event) is True


def test_does_not_match_unrelated(uet) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert uet.matches(event) is False


@pytest.mark.parametrize("key", ["mid", "vid"])
def test_persistent_identifiers_high(uet, key: str) -> None:
    event = make_request(host="bat.bing.com", url=f"https://bat.bing.com/?{key}=x")
    hit = uet.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["sid", "pi", "msclkid"])
def test_other_identifiers(uet, key: str) -> None:
    event = make_request(host="bat.bing.com", url=f"https://bat.bing.com/?{key}=x")
    hit = uet.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


@pytest.mark.parametrize("key", ["ti", "gid"])
def test_property_ids_are_technical(uet, key: str) -> None:
    event = make_request(host="bat.bing.com", url=f"https://bat.bing.com/?{key}=x")
    hit = uet.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize("key", ["MXFR", "uid"])
def test_cookie_sync_identifiers_high(uet, key: str) -> None:
    event = make_request(host="c.bing.com", url=f"https://c.bing.com/c.gif?{key}=x")
    hit = uet.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["evt", "ec", "ea", "el", "ev", "gv", "src", "vids"])
def test_behavioral(uet, key: str) -> None:
    event = make_request(host="bat.bing.com", url=f"https://bat.bing.com/?{key}=x")
    hit = uet.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_BEHAVIORAL


@pytest.mark.parametrize("key", ["p", "r", "tl", "kw", "RedC", "Red3"])
def test_content(uet, key: str) -> None:
    event = make_request(host="bat.bing.com", url=f"https://bat.bing.com/?{key}=x")
    hit = uet.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["cdb", "asc", "gdpr", "gdpr_consent"])
def test_consent(uet, key: str) -> None:
    event = make_request(host="bat.bing.com", url=f"https://bat.bing.com/?{key}=1")
    hit = uet.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


@pytest.mark.parametrize("key", ["lg", "sw", "sh", "sc", "tz", "Ver", "tm", "bo", "rn"])
def test_technical(uet, key: str) -> None:
    event = make_request(host="bat.bing.com", url=f"https://bat.bing.com/?{key}=x")
    hit = uet.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param(uet) -> None:
    event = make_request(host="bat.bing.com", url="https://bat.bing.com/?weird=1")
    hit = uet.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Bing UET" in p.meaning
