"""Tests for the OpenStreetMap / Nominatim module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONTENT,
    CAT_OTHER,
    CAT_PII,
    CAT_TECHNICAL,
    IMPACT_HIGH,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def osm():
    return module_by_id("openstreetmap")


def test_identity(osm) -> None:
    assert osm.module_id == "openstreetmap"
    assert osm.module_name == "OpenStreetMap / Nominatim"
    assert osm.legal_jurisdiction == "UK"  # EU-friendly map provider


@pytest.mark.parametrize(
    "host",
    [
        "openstreetmap.org",
        "tile.openstreetmap.org",
        "a.tile.openstreetmap.org",
        "nominatim.openstreetmap.org",
        "routing.openstreetmap.de",
    ],
)
def test_matches(osm, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert osm.matches(event) is True


def test_does_not_match_unrelated(osm) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert osm.matches(event) is False


def test_email_is_pii_high(osm) -> None:
    """Nominatim usage-policy requests an email — that's PII."""
    event = make_request(
        host="nominatim.openstreetmap.org",
        url="https://nominatim.openstreetmap.org/search?q=Brussels&email=ops@example.com",
    )
    hit = osm.parse(event)
    p = next(p for p in hit.params if p.key == "email")
    assert p.category == CAT_PII
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize(
    "key", ["q", "street", "city", "country", "lat", "lon", "viewbox"],
)
def test_content_params(osm, key: str) -> None:
    event = make_request(host="nominatim.openstreetmap.org", url=f"https://nominatim.openstreetmap.org/?{key}=x")
    hit = osm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["format", "addressdetails", "limit", "zoom"])
def test_technical(osm, key: str) -> None:
    event = make_request(host="nominatim.openstreetmap.org", url=f"https://nominatim.openstreetmap.org/?{key}=x")
    hit = osm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param(osm) -> None:
    event = make_request(host="nominatim.openstreetmap.org", url="https://nominatim.openstreetmap.org/?weird=1")
    hit = osm.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "OSM" in p.meaning or "Nominatim" in p.meaning
