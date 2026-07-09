"""Tests for the hCaptcha module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def hc():
    return module_by_id("hcaptcha")


def test_identity(hc) -> None:
    assert hc.module_id == "hcaptcha"
    assert hc.module_name == "hCaptcha"
    assert hc.vendor == "Intuition Machines, Inc."


@pytest.mark.parametrize(
    "host", ["hcaptcha.com", "newassets.hcaptcha.com"],
)
def test_matches(hc, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/1/api.js")
    assert hc.matches(event) is True


def test_does_not_match_unrelated(hc) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert hc.matches(event) is False


@pytest.mark.parametrize("key", ["id", "rqdata"])
def test_identifiers(hc, key: str) -> None:
    event = make_request(host="hcaptcha.com", url=f"https://hcaptcha.com/1/api.js?{key}=x")
    hit = hc.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


@pytest.mark.parametrize(
    "key", ["sitekey", "theme", "size", "hl", "callback", "error-callback", "endpoint", "v"],
)
def test_technical(hc, key: str) -> None:
    event = make_request(host="hcaptcha.com", url=f"https://hcaptcha.com/1/api.js?{key}=x")
    hit = hc.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param_falls_through(hc) -> None:
    event = make_request(host="hcaptcha.com", url="https://hcaptcha.com/1/api.js?weird=1")
    hit = hc.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "hCaptcha" in p.meaning
