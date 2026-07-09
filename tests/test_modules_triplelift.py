"""Tests for the TripleLift module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONSENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_HIGH,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def tl():
    return module_by_id("triplelift")


def test_identity(tl) -> None:
    assert tl.module_id == "triplelift"
    assert tl.module_name == "TripleLift"
    assert tl.legal_jurisdiction == "US"


@pytest.mark.parametrize(
    "host", ["3lift.com", "dmpsync.3lift.com", "ib.3lift.com"],
)
def test_matches(tl, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/getuid")
    assert tl.matches(event) is True


def test_does_not_match_unrelated(tl) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert tl.matches(event) is False


def test_tl_uid_is_high_impact(tl) -> None:
    """``tl_uid`` is TripleLift's persistent visitor pseudonym."""
    event = make_request(host="ib.3lift.com", url="https://ib.3lift.com/getuid?tl_uid=ABC")
    hit = tl.parse(event)
    p = next(p for p in hit.params if p.key == "tl_uid")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


def test_uid_is_high_impact(tl) -> None:
    event = make_request(host="ib.3lift.com", url="https://ib.3lift.com/getuid?uid=PARTNER")
    hit = tl.parse(event)
    p = next(p for p in hit.params if p.key == "uid")
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["pid", "redir", "r"])
def test_redirect_keys(tl, key: str) -> None:
    event = make_request(host="ib.3lift.com", url=f"https://ib.3lift.com/?{key}=x")
    hit = tl.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


@pytest.mark.parametrize("key", ["gdpr", "gdpr_consent", "us_privacy"])
def test_consent_keys(tl, key: str) -> None:
    event = make_request(host="ib.3lift.com", url=f"https://ib.3lift.com/?{key}=1")
    hit = tl.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


def test_unknown_param_falls_through(tl) -> None:
    event = make_request(host="ib.3lift.com", url="https://ib.3lift.com/?weird=1")
    hit = tl.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "TripleLift" in p.meaning
