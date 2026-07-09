"""Tests for the Squarespace platform-infrastructure module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_TECHNICAL

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("squarespace")


def test_identity(m) -> None:
    assert m.module_id == "squarespace"
    assert m.module_name == "Squarespace"
    assert m.vendor.startswith("Squarespace")
    assert m.legal_jurisdiction == "US"


@pytest.mark.parametrize(
    "host",
    [
        "static1.squarespace.com",
        "assets.squarespace.com",
        "images.squarespace-cdn.com",
        "video.squarespace-cdn.com",
        "definitions.sqspcdn.com",
    ],
)
def test_matches_squarespace_hosts(m, host) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert m.matches(event) is True


def test_does_not_match_unrelated(m) -> None:
    for host in ("example.com", "www.squarespace.com.evil.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


def test_asset_params_are_technical(m) -> None:
    event = make_request(
        host="images.squarespace-cdn.com",
        url="https://images.squarespace-cdn.com/content/v1/x/logo.png?format=1500w",
    )
    cats = {p.key: p.category for p in m.parse(event).params}
    assert cats["format"] == CAT_TECHNICAL