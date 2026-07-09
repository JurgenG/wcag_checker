"""Tests for the TubeMogul module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONSENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def tm():
    return module_by_id("tubemogul")


def test_identity(tm) -> None:
    assert tm.module_id == "tubemogul"
    assert tm.module_name == "TubeMogul (Adobe Advertising Cloud)"
    assert tm.legal_jurisdiction == "US"


@pytest.mark.parametrize(
    "host", ["tubemogul.com", "rtd.tubemogul.com", "ag.tubemogul.com"],
)
def test_matches(tm, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/upi/pid/abc")
    assert tm.matches(event) is True


def test_does_not_match_unrelated(tm) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert tm.matches(event) is False


@pytest.mark.parametrize("key", ["uid"])
def test_classify_identifiers(tm, key: str) -> None:
    event = make_request(host="rtd.tubemogul.com", url=f"https://rtd.tubemogul.com/?{key}=x")
    hit = tm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


@pytest.mark.parametrize("key", ["pid", "redir", "r"])
def test_classify_redirects(tm, key: str) -> None:
    event = make_request(host="rtd.tubemogul.com", url=f"https://rtd.tubemogul.com/?{key}=x")
    hit = tm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


@pytest.mark.parametrize("key", ["gdpr", "gdpr_consent", "us_privacy"])
def test_classify_consent(tm, key: str) -> None:
    event = make_request(host="rtd.tubemogul.com", url=f"https://rtd.tubemogul.com/?{key}=1")
    hit = tm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


def test_unknown_param_falls_through(tm) -> None:
    event = make_request(host="rtd.tubemogul.com", url="https://rtd.tubemogul.com/?weird=1")
    hit = tm.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "TubeMogul" in p.meaning
