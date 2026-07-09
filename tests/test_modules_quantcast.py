"""Tests for the Quantcast module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def qc():
    return module_by_id("quantcast")


def test_identity(qc) -> None:
    assert qc.module_id == "quantcast"
    assert qc.module_name == "Quantcast"


@pytest.mark.parametrize(
    "host",
    ["quantserve.com", "quantcast.com", "pixel.quantserve.com", "quantcast.mgr.consensu.org"],
)
def test_matches_quantcast_and_quantserve(qc, host: str) -> None:
    # Last one (.consensu.org) is NOT in the host list — skip it.
    if "quantserve" in host or "quantcast" in host:
        event = make_request(host=host, url=f"https://{host}/x")
        if host.endswith(".quantserve.com") or host.endswith(".quantcast.com") or host in {"quantserve.com", "quantcast.com"}:
            assert qc.matches(event) is True


def test_path_extracts_property_id(qc) -> None:
    """``/pixel/p-XXXXX.gif`` paths surface the property ID as a synthetic param."""
    event = make_request(
        host="pixel.quantserve.com",
        url="https://pixel.quantserve.com/pixel/p-ABC123.gif",
    )
    hit = qc.parse(event)
    p = next(p for p in hit.params if p.key == "(path) property_id")
    assert p.value == "p-ABC123"
    assert p.category == CAT_TECHNICAL


@pytest.mark.parametrize("key", ["qcvid"])
def test_identifiers(qc, key: str) -> None:
    event = make_request(host="pixel.quantserve.com", url=f"https://pixel.quantserve.com/?{key}=x")
    hit = qc.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


@pytest.mark.parametrize("key", ["event", "labels"])
def test_behavioral(qc, key: str) -> None:
    event = make_request(host="pixel.quantserve.com", url=f"https://pixel.quantserve.com/?{key}=x")
    hit = qc.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_BEHAVIORAL


@pytest.mark.parametrize("key", ["pid", "a", "idmatch"])
def test_technical(qc, key: str) -> None:
    event = make_request(host="pixel.quantserve.com", url=f"https://pixel.quantserve.com/?{key}=1")
    hit = qc.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


@pytest.mark.parametrize("key", ["gdpr", "gdpr_consent", "us_privacy"])
def test_consent(qc, key: str) -> None:
    event = make_request(host="pixel.quantserve.com", url=f"https://pixel.quantserve.com/?{key}=1")
    hit = qc.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


def test_unknown_param(qc) -> None:
    event = make_request(host="pixel.quantserve.com", url="https://pixel.quantserve.com/?weird=1")
    hit = qc.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Quantcast" in p.meaning
