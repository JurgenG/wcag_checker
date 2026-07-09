"""Tests for the IAS module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def ias():
    return module_by_id("integral_ad_science")


def test_identity(ias) -> None:
    assert ias.module_id == "integral_ad_science"
    assert ias.module_name == "Integral Ad Science"


@pytest.mark.parametrize(
    "host",
    [
        "adsafeprotected.com",
        "dt.adsafeprotected.com",
        "pixel.adsafeprotected.com",
        "static.adsafeprotected.com",
    ],
)
def test_matches(ias, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/dt")
    assert ias.matches(event) is True


@pytest.mark.parametrize(
    "key", ["ias_impId", "asId"],
)
def test_identifiers(ias, key: str) -> None:
    event = make_request(host="dt.adsafeprotected.com", url=f"https://dt.adsafeprotected.com/?{key}=x")
    hit = ias.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


def test_adsafe_url_is_content(ias) -> None:
    event = make_request(
        host="dt.adsafeprotected.com",
        url="https://dt.adsafeprotected.com/dt?adsafe_url=https://example.com/article",
    )
    hit = ias.parse(event)
    p = next(p for p in hit.params if p.key == "adsafe_url")
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize(
    "key",
    ["ias_campId", "ias_creativeId", "ias_placementId", "advEntityId",
     "adsafe_jsinfo", "cbName"],
)
def test_technical(ias, key: str) -> None:
    event = make_request(host="dt.adsafeprotected.com", url=f"https://dt.adsafeprotected.com/?{key}=x")
    hit = ias.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param_falls_through(ias) -> None:
    event = make_request(host="dt.adsafeprotected.com", url="https://dt.adsafeprotected.com/?advId=quantcast")
    hit = ias.parse(event)
    p = next(p for p in hit.params if p.key == "advId")
    assert p.category == CAT_OTHER
    assert "IAS" in p.meaning
