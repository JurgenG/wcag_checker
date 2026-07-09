"""Tests for the Duda platform-infrastructure module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_BEHAVIORAL, CAT_TECHNICAL

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("duda")


def test_identity(m) -> None:
    assert m.module_id == "duda"
    assert m.module_name == "Duda"
    assert m.vendor.startswith("Duda")
    assert m.legal_jurisdiction == "US"


@pytest.mark.parametrize(
    "host",
    [
        "de-ms-cdn.multiscreensite.com",
        "ms-cdn.multiscreensite.com",
        "irp-cdn.multiscreensite.com",
        "rtc.multiscreensite.com",
        "rtc.eu-multiscreensite.com",
        "irp.cdn-website.com",
        "lirp.cdn-website.com",
        "static.cdn-website.com",
    ],
)
def test_matches_duda_hosts(m, host) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert m.matches(event) is True


def test_does_not_match_unrelated(m) -> None:
    for host in ("example.com", "notmultiscreensite.com.evil.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


def test_has_telemetry_beacon_privacy_rating(m) -> None:
    """rtc.multiscreensite.com is Duda's performance-metrics beacon."""
    assert m.impact_rating.privacy == 1.5


def test_beacon_params_are_behavioral_assets_technical(m) -> None:
    beacon = make_request(
        host="rtc.multiscreensite.com",
        url="https://rtc.multiscreensite.com/performance/metrics?t=load",
        method="POST",
    )
    asset = make_request(
        host="ms-cdn.multiscreensite.com",
        url="https://ms-cdn.multiscreensite.com/runtime-react/4211/x.js?v=2",
    )
    assert {p.key: p.category for p in m.parse(beacon).params}["t"] == CAT_BEHAVIORAL
    assert {p.key: p.category for p in m.parse(asset).params}["v"] == CAT_TECHNICAL
