"""Tests for the Bing Maps module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_LOW,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def bm():
    return module_by_id("bing_maps")


def test_identity(bm) -> None:
    assert bm.module_id == "bing_maps"
    assert bm.module_name == "Bing Maps"
    assert bm.vendor == "Microsoft Corporation"


@pytest.mark.parametrize(
    "host", ["virtualearth.net", "dev.virtualearth.net", "t0.tiles.virtualearth.net"],
)
def test_matches(bm, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/REST/v1/Locations")
    assert bm.matches(event) is True


def test_does_not_match_bing_com(bm) -> None:
    event = make_request(host="www.bing.com", url="https://www.bing.com/maps")
    assert bm.matches(event) is False


@pytest.mark.parametrize("key", ["session"])
def test_identifiers(bm, key: str) -> None:
    event = make_request(host="dev.virtualearth.net", url=f"https://dev.virtualearth.net/?{key}=x")
    hit = bm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


@pytest.mark.parametrize("key", ["key", "AuthKey"])
def test_property_ids_are_technical(bm, key: str) -> None:
    event = make_request(host="dev.virtualearth.net", url=f"https://dev.virtualearth.net/?{key}=x")
    hit = bm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize(
    "key", ["query", "q", "addressLine", "point", "centerPoint", "mapArea", "wp"],
)
def test_search_and_location_are_content(bm, key: str) -> None:
    event = make_request(host="dev.virtualearth.net", url=f"https://dev.virtualearth.net/?{key}=x")
    hit = bm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize(
    "key", ["o", "output", "c", "ur", "lvl", "version", "callback"],
)
def test_technical(bm, key: str) -> None:
    event = make_request(host="dev.virtualearth.net", url=f"https://dev.virtualearth.net/?{key}=x")
    hit = bm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param(bm) -> None:
    event = make_request(host="dev.virtualearth.net", url="https://dev.virtualearth.net/?weird=1")
    hit = bm.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Bing Maps" in p.meaning
