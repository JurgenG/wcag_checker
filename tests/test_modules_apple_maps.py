"""Tests for the Apple Maps module."""

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
def am():
    return module_by_id("apple_maps")


def test_identity(am) -> None:
    assert am.module_id == "apple_maps"
    assert am.module_name == "Apple Maps / MapKit JS"
    assert am.vendor == "Apple Inc."


@pytest.mark.parametrize(
    "host",
    [
        "maps.apple.com",
        "apple-mapkit.com",
        "cdn.apple-mapkit.com",
        "gsp10-ssl.apple.com",
        "gsp64-ssl.ls.apple.com",
        "gspe19-ssl.ls.apple.com",
    ],
)
def test_matches(am, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert am.matches(event) is True


def test_does_not_match_bare_apple_com(am) -> None:
    """``apple.com`` itself serves the marketing site, not the Maps service."""
    event = make_request(host="apple.com", url="https://apple.com/")
    assert am.matches(event) is False


@pytest.mark.parametrize("key", ["token", "team"])
def test_identifiers(am, key: str) -> None:
    event = make_request(host="cdn.apple-mapkit.com", url=f"https://cdn.apple-mapkit.com/?{key}=x")
    hit = am.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


@pytest.mark.parametrize(
    "key", ["q", "address", "ll", "coordinate", "near", "origin", "destination", "saddr"],
)
def test_content(am, key: str) -> None:
    event = make_request(host="cdn.apple-mapkit.com", url=f"https://cdn.apple-mapkit.com/?{key}=x")
    hit = am.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["z", "t", "language", "v", "callback"])
def test_technical(am, key: str) -> None:
    event = make_request(host="cdn.apple-mapkit.com", url=f"https://cdn.apple-mapkit.com/?{key}=x")
    hit = am.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param(am) -> None:
    event = make_request(host="cdn.apple-mapkit.com", url="https://cdn.apple-mapkit.com/?weird=1")
    hit = am.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Apple Maps" in p.meaning
