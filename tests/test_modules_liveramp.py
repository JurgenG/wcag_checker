"""Tests for the LiveRamp module."""

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
def lr():
    return module_by_id("liveramp")


def test_identity(lr) -> None:
    assert lr.module_id == "liveramp"
    assert lr.module_name == "LiveRamp"


@pytest.mark.parametrize("host", ["rlcdn.com", "idsync.rlcdn.com"])
def test_matches(lr, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/365868.gif")
    assert lr.matches(event) is True


def test_does_not_match_unrelated(lr) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert lr.matches(event) is False


def test_path_extracts_partner_id(lr) -> None:
    """``/<digits>.gif`` paths surface the partner ID as a synthetic param."""
    event = make_request(host="idsync.rlcdn.com", url="https://idsync.rlcdn.com/365868.gif")
    hit = lr.parse(event)
    p = next(p for p in hit.params if p.key == "(path) partner_id")
    assert p.value == "365868"
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


def test_partner_uid_is_high_impact(lr) -> None:
    event = make_request(host="idsync.rlcdn.com", url="https://idsync.rlcdn.com/?partner_uid=ABC")
    hit = lr.parse(event)
    p = next(p for p in hit.params if p.key == "partner_uid")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


def test_other_identifiers(lr) -> None:
    event = make_request(host="idsync.rlcdn.com", url="https://idsync.rlcdn.com/?uid=x")
    hit = lr.parse(event)
    p = next(p for p in hit.params if p.key == "uid")
    assert p.category == CAT_IDENTIFIER


def test_pid_is_technical(lr) -> None:
    """``pid`` is the partner / publisher account ID — TECHNICAL / LOW."""
    event = make_request(host="idsync.rlcdn.com", url="https://idsync.rlcdn.com/?pid=x")
    hit = lr.parse(event)
    p = next(p for p in hit.params if p.key == "pid")
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize("key", ["r", "redir"])
def test_redirect(lr, key: str) -> None:
    event = make_request(host="idsync.rlcdn.com", url=f"https://idsync.rlcdn.com/?{key}=x")
    hit = lr.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


@pytest.mark.parametrize("key", ["gdpr", "gdpr_consent", "us_privacy"])
def test_consent(lr, key: str) -> None:
    event = make_request(host="idsync.rlcdn.com", url=f"https://idsync.rlcdn.com/?{key}=1")
    hit = lr.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


def test_unknown_param(lr) -> None:
    event = make_request(host="idsync.rlcdn.com", url="https://idsync.rlcdn.com/?weird=1")
    hit = lr.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "LiveRamp" in p.meaning
