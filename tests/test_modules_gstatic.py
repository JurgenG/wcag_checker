"""Tests for the gstatic (Google static CDN) tracker module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def gs():
    return module_by_id("gstatic")


def test_identity(gs) -> None:
    assert gs.module_id == "gstatic"
    assert gs.module_name == "Google static CDN (gstatic)"
    assert gs.vendor == "Google LLC"
    assert gs.legal_jurisdiction == "US"
    assert gs.data_residency
    assert gs.sovereignty_notes


@pytest.mark.parametrize(
    "host",
    [
        "gstatic.com",
        "www.gstatic.com",
        "csi.gstatic.com",
        "ssl.gstatic.com",
        "anything.gstatic.com",
    ],
)
def test_matches_gstatic_apex_and_subdomains(gs, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/foo.png")
    assert gs.matches(event) is True


def test_matches_is_case_insensitive(gs) -> None:
    event = make_request(host="WWW.GSTATIC.COM", url="https://WWW.GSTATIC.COM/x")
    assert gs.matches(event) is True


def test_does_not_match_lookalike_host(gs) -> None:
    """``notgstatic.com`` must NOT match — suffix check is on '.gstatic.com'."""
    event = make_request(host="notgstatic.com", url="https://notgstatic.com/")
    assert gs.matches(event) is False


def test_does_not_match_unrelated_host(gs) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert gs.matches(event) is False


def test_parse_hit_metadata(gs) -> None:
    event = make_request(
        host="www.gstatic.com",
        url="https://www.gstatic.com/youtube/img/player.png",
        event_id=99,
    )
    hit = gs.parse(event)
    assert isinstance(hit, Hit)
    assert hit.module_id == "gstatic"
    assert hit.events == [99]


@pytest.mark.parametrize(
    "key",
    ["ver", "v", "hl", "_", "kid"],
)
def test_classify_known_params_are_technical_low(gs, key: str) -> None:
    event = make_request(
        host="www.gstatic.com",
        url=f"https://www.gstatic.com/img.png?{key}=42",
    )
    hit = gs.parse(event)
    param = next(p for p in hit.params if p.key == key)
    assert param.category == CAT_TECHNICAL
    assert param.privacy_impact == IMPACT_LOW


def test_classify_unknown_param_falls_through(gs) -> None:
    event = make_request(
        host="www.gstatic.com",
        url="https://www.gstatic.com/img.png?unknown=x",
    )
    hit = gs.parse(event)
    param = next(p for p in hit.params if p.key == "unknown")
    assert param.category == CAT_OTHER
    assert param.privacy_impact == IMPACT_LOW
    assert "gstatic" in param.meaning
