"""Tests for the Magnite (Rubicon Project) module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONSENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_HIGH,
    IMPACT_LOW,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def mg():
    return module_by_id("magnite")


def test_identity(mg) -> None:
    assert mg.module_id == "magnite"
    assert mg.module_name == "Magnite (Rubicon Project)"
    assert mg.legal_jurisdiction == "US"


@pytest.mark.parametrize(
    "host", ["rubiconproject.com", "magnite.com", "pixel.rubiconproject.com"],
)
def test_matches(mg, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/tap.php")
    assert mg.matches(event) is True


def test_does_not_match_unrelated(mg) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert mg.matches(event) is False


def test_put_is_high_impact(mg) -> None:
    """``put`` is the partner-supplied UID being persisted into Magnite."""
    event = make_request(
        host="pixel.rubiconproject.com",
        url="https://pixel.rubiconproject.com/tap.php?put=USERID",
    )
    hit = mg.parse(event)
    p = next(p for p in hit.params if p.key == "put")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["v", "nid"])
def test_other_identifiers(mg, key: str) -> None:
    event = make_request(host="pixel.rubiconproject.com", url=f"https://pixel.rubiconproject.com/?{key}=x")
    hit = mg.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize("key", ["gdpr", "gdpr_consent", "us_privacy"])
def test_consent(mg, key: str) -> None:
    event = make_request(host="pixel.rubiconproject.com", url=f"https://pixel.rubiconproject.com/?{key}=1")
    hit = mg.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


def test_redirect_is_technical(mg) -> None:
    event = make_request(host="pixel.rubiconproject.com", url="https://pixel.rubiconproject.com/?redirect=https://x")
    hit = mg.parse(event)
    p = next(p for p in hit.params if p.key == "redirect")
    assert p.category == CAT_TECHNICAL


def test_unknown_param_falls_through(mg) -> None:
    event = make_request(host="pixel.rubiconproject.com", url="https://pixel.rubiconproject.com/?weird=1")
    hit = mg.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Magnite" in p.meaning
