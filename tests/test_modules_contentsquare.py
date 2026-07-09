"""Tests for the Contentsquare (ClickTale) module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_HIGH,
    IMPACT_LOW,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def cs():
    return module_by_id("contentsquare")


def test_identity(cs) -> None:
    assert cs.module_id == "contentsquare"
    assert cs.legal_jurisdiction == "FR"


@pytest.mark.parametrize(
    "host",
    [
        "clicktale.net",
        "c.az.clicktale.net",
        "contentsquare.net",
        "static.hj.contentsquare.net",
        "k.af.clicktale.net",
    ],
)
def test_matches(cs, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert cs.matches(event) is True


def test_uu_is_high_impact(cs) -> None:
    """``uu`` is the persistent visitor UUID."""
    event = make_request(host="c.az.clicktale.net", url="https://c.az.clicktale.net/pageview?uu=ABC")
    hit = cs.parse(event)
    p = next(p for p in hit.params if p.key == "uu")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["ri"])
def test_other_identifiers(cs, key: str) -> None:
    event = make_request(host="c.az.clicktale.net", url=f"https://c.az.clicktale.net/?{key}=x")
    hit = cs.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


def test_pid_is_technical_low(cs) -> None:
    """``pid`` is the per-customer Contentsquare project ID — technical, low impact."""
    event = make_request(host="c.az.clicktale.net", url="https://c.az.clicktale.net/?pid=x")
    hit = cs.parse(event)
    p = next(p for p in hit.params if p.key == "pid")
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize("key", ["url", "dr", "fvurl", "t"])
def test_content(cs, key: str) -> None:
    event = make_request(host="c.az.clicktale.net", url=f"https://c.az.clicktale.net/?{key}=x")
    hit = cs.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["v", "sn", "pn", "r", "fvt", "cvt", "dw", "dh", "ww", "wh", "sw", "sh", "la"])
def test_technical(cs, key: str) -> None:
    event = make_request(host="c.az.clicktale.net", url=f"https://c.az.clicktale.net/?{key}=x")
    hit = cs.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param(cs) -> None:
    event = make_request(host="c.az.clicktale.net", url="https://c.az.clicktale.net/?weird=1")
    hit = cs.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Contentsquare" in p.meaning
