"""Tests for the Taboola module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def tb():
    return module_by_id("taboola")


def test_identity(tb) -> None:
    assert tb.module_id == "taboola"
    assert tb.module_name == "Taboola"
    assert tb.legal_jurisdiction == "IL"


@pytest.mark.parametrize(
    "host", ["taboola.com", "trc.taboola.com", "cdn.taboola.com", "vidstat.taboola.com"],
)
def test_matches(tb, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert tb.matches(event) is True


def test_path_extracts_partner_from_sg(tb) -> None:
    event = make_request(
        host="trc.taboola.com",
        url="https://trc.taboola.com/sg/publisher-foo/1.0/cm",
    )
    hit = tb.parse(event)
    p = next(p for p in hit.params if p.key == "(path) partner")
    assert p.value == "publisher-foo"
    assert p.category == CAT_TECHNICAL


def test_path_extracts_partner_from_libtrc(tb) -> None:
    event = make_request(
        host="cdn.taboola.com",
        url="https://cdn.taboola.com/libtrc/publisher-bar/loader.js",
    )
    hit = tb.parse(event)
    p = next(p for p in hit.params if p.key == "(path) partner")
    assert p.value == "publisher-bar"


@pytest.mark.parametrize("key", ["tabid"])
def test_identifiers(tb, key: str) -> None:
    event = make_request(host="trc.taboola.com", url=f"https://trc.taboola.com/?{key}=x")
    hit = tb.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


@pytest.mark.parametrize("key", ["partner", "pid", "pubid"])
def test_technical(tb, key: str) -> None:
    event = make_request(host="trc.taboola.com", url=f"https://trc.taboola.com/?{key}=x")
    hit = tb.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


@pytest.mark.parametrize("key", ["event", "name"])
def test_behavioral(tb, key: str) -> None:
    event = make_request(host="trc.taboola.com", url=f"https://trc.taboola.com/?{key}=x")
    hit = tb.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_BEHAVIORAL


@pytest.mark.parametrize("key", ["url", "referrer", "title"])
def test_content(tb, key: str) -> None:
    event = make_request(host="trc.taboola.com", url=f"https://trc.taboola.com/?{key}=x")
    hit = tb.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["gdpr", "gdpr_consent", "us_privacy"])
def test_consent(tb, key: str) -> None:
    event = make_request(host="trc.taboola.com", url=f"https://trc.taboola.com/?{key}=1")
    hit = tb.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


def test_unknown_param(tb) -> None:
    event = make_request(host="trc.taboola.com", url="https://trc.taboola.com/?weird=1")
    hit = tb.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Taboola" in p.meaning
