"""Tests for the AppNexus / Xandr module."""

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
def an():
    return module_by_id("appnexus")


def test_identity(an) -> None:
    assert an.module_id == "appnexus"
    assert an.module_name == "AppNexus / Xandr"


@pytest.mark.parametrize(
    "host", ["adnxs.com", "ib.adnxs.com", "ams3-ib.adnxs.com", "acdn.adnxs.com", "secure.adnxs.com"],
)
def test_matches(an, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert an.matches(event) is True


def test_uid_is_high_impact(an) -> None:
    """``uid`` is the AppNexus persistent visitor pseudonym (uuid2 cookie)."""
    event = make_request(host="ib.adnxs.com", url="https://ib.adnxs.com/?uid=ABC")
    hit = an.parse(event)
    p = next(p for p in hit.params if p.key == "uid")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["pub_id", "seller_id", "bidder", "tag_id"])
def test_other_identifiers(an, key: str) -> None:
    event = make_request(host="ib.adnxs.com", url=f"https://ib.adnxs.com/?{key}=x")
    hit = an.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize("key", ["e", "vd"])
def test_event_payload_behavioral(an, key: str) -> None:
    event = make_request(host="ib.adnxs.com", url=f"https://ib.adnxs.com/vevent?{key}=x")
    hit = an.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_BEHAVIORAL


@pytest.mark.parametrize("key", ["referrer", "bdref", "bdtop", "bstk"])
def test_content(an, key: str) -> None:
    event = make_request(host="ib.adnxs.com", url=f"https://ib.adnxs.com/?{key}=x")
    hit = an.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["gdpr", "gdpr_consent", "gpp", "gpp_sid", "addtl_consent", "google_cver"])
def test_consent(an, key: str) -> None:
    event = make_request(host="ib.adnxs.com", url=f"https://ib.adnxs.com/?{key}=1")
    hit = an.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


@pytest.mark.parametrize("key", ["pl", "ua", "tv", "ww", "wh", "sw", "sh", "ph", "an_audit", "s", "cbfn"])
def test_technical(an, key: str) -> None:
    event = make_request(host="ib.adnxs.com", url=f"https://ib.adnxs.com/?{key}=x")
    hit = an.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param(an) -> None:
    event = make_request(host="ib.adnxs.com", url="https://ib.adnxs.com/?weird=1")
    hit = an.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "AppNexus" in p.meaning
