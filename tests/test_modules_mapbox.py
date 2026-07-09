"""Tests for the Mapbox module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONTENT,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_LOW,
    IMPACT_MEDIUM,
)
from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("mapbox")


def test_identity(m) -> None:
    assert m.module_id == "mapbox"
    assert m.module_name == "Mapbox"
    assert m.vendor == "Mapbox, Inc."
    assert m.legal_jurisdiction == "US"
    assert m.data_residency and m.sovereignty_notes


@pytest.mark.parametrize("host", ["api.mapbox.com", "events.mapbox.com", "a.tiles.mapbox.com"])
def test_matches_hosts(m, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/mapbox-gl-js/v1.8.1/mapbox-gl.css")
    assert m.matches(event) is True


def test_case_insensitive(m) -> None:
    event = make_request(host="API.MAPBOX.COM", url="https://API.MAPBOX.COM/x")
    assert m.matches(event) is True


def test_rejects_lookalike(m) -> None:
    event = make_request(host="mapbox.com.evil.example", url="https://mapbox.com.evil.example/x")
    assert m.matches(event) is False


@pytest.mark.parametrize(
    ("key", "category", "impact"),
    [
        ("access_token", CAT_TECHNICAL, IMPACT_LOW),
        ("q", CAT_CONTENT, IMPACT_MEDIUM),
        ("proximity", CAT_CONTENT, IMPACT_MEDIUM),
    ],
)
def test_known_params(m, key, category, impact) -> None:
    event = make_request(
        host="api.mapbox.com",
        url=f"https://api.mapbox.com/geocoding/v5/mapbox.places/x.json?{key}=v",
    )
    hit = m.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == category
    assert p.privacy_impact == impact


def test_unknown_param_is_other(m) -> None:
    event = make_request(host="api.mapbox.com", url="https://api.mapbox.com/x?weird=1")
    hit = m.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Mapbox" in p.meaning
