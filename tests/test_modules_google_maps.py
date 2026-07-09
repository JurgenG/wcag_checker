"""Tests for the Google Maps module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONTENT,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_LOW,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def gm():
    return module_by_id("google_maps")


def test_identity(gm) -> None:
    assert gm.module_id == "google_maps"
    assert gm.module_name == "Google Maps"


@pytest.mark.parametrize(
    "host",
    [
        "maps.googleapis.com", "maps.gstatic.com", "maps.google.com",
        "mts0.google.com", "khms0.google.com",
    ],
)
def test_matches_exact_hosts(gm, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert gm.matches(event) is True


def test_does_not_match_other_googleapis(gm) -> None:
    """Other ``googleapis.com`` subdomains are NOT claimed by Maps."""
    event = make_request(host="storage.googleapis.com", url="https://storage.googleapis.com/")
    assert gm.matches(event) is False


@pytest.mark.parametrize("key", ["key", "client", "channel"])
def test_property_ids_are_technical(gm, key: str) -> None:
    event = make_request(host="maps.googleapis.com", url=f"https://maps.googleapis.com/maps/api?{key}=x")
    hit = gm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize(
    "key", ["q", "address", "latlng", "destination", "origin", "waypoints", "location", "pano"],
)
def test_content_search_keys(gm, key: str) -> None:
    event = make_request(host="maps.googleapis.com", url=f"https://maps.googleapis.com/maps/api?{key}=x")
    hit = gm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["v", "language", "region", "zoom", "scale", "maptype"])
def test_technical(gm, key: str) -> None:
    event = make_request(host="maps.googleapis.com", url=f"https://maps.googleapis.com/maps/api?{key}=x")
    hit = gm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param(gm) -> None:
    event = make_request(host="maps.googleapis.com", url="https://maps.googleapis.com/maps/api?weird=1")
    hit = gm.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Google Maps" in p.meaning
