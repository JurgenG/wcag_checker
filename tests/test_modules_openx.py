"""Tests for the OpenX SSP module."""

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
def ox():
    return module_by_id("openx")


def test_identity(ox) -> None:
    assert ox.module_id == "openx"
    assert ox.module_name == "OpenX"
    assert ox.legal_jurisdiction == "US"


@pytest.mark.parametrize(
    "host", ["openx.net", "us-u.openx.net", "eu-u.openx.net", "rtb.openx.net"],
)
def test_matches(ox, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/w/1.0/sd")
    assert ox.matches(event) is True


def test_does_not_match_unrelated(ox) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert ox.matches(event) is False


def test_val_is_high_impact_identifier(ox) -> None:
    """``val`` is the partner-supplied user ID being persisted — high impact."""
    event = make_request(host="us-u.openx.net", url="https://us-u.openx.net/w/1.0/sd?val=USERID")
    hit = ox.parse(event)
    p = next(p for p in hit.params if p.key == "val")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["id", "pid"])
def test_other_identifiers_are_technical(ox, key: str) -> None:
    event = make_request(host="us-u.openx.net", url=f"https://us-u.openx.net/?{key}=x")
    hit = ox.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize("key", ["gdpr", "gdpr_consent", "us_privacy"])
def test_consent_params(ox, key: str) -> None:
    event = make_request(host="us-u.openx.net", url=f"https://us-u.openx.net/?{key}=1")
    hit = ox.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


def test_unknown_param_falls_through(ox) -> None:
    event = make_request(host="us-u.openx.net", url="https://us-u.openx.net/?weird=1")
    hit = ox.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "OpenX" in p.meaning
