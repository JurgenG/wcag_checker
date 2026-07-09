"""Tests for the FullStory session-replay module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_PII,
    CAT_TECHNICAL,
    IMPACT_HIGH,
    IMPACT_LOW,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def fs():
    return module_by_id("fullstory")


def test_identity(fs) -> None:
    assert fs.module_id == "fullstory"
    assert fs.module_name == "FullStory"
    assert fs.legal_jurisdiction == "US"


@pytest.mark.parametrize(
    "host", ["fullstory.com", "edge.fullstory.com", "rs.fullstory.com"],
)
def test_matches(fs, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/rec/bundle")
    assert fs.matches(event) is True


def test_does_not_match_unrelated(fs) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert fs.matches(event) is False


def test_userid_is_high_impact_identifier(fs) -> None:
    """``UserId`` is the persistent FullStory visitor pseudonym."""
    event = make_request(host="rs.fullstory.com", url="https://rs.fullstory.com/rec/bundle?UserId=ABC")
    hit = fs.parse(event)
    p = next(p for p in hit.params if p.key == "UserId")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


def test_uid_is_pii_high(fs) -> None:
    """``Uid`` is site-supplied user identity (Identify API) — PII."""
    event = make_request(host="rs.fullstory.com", url="https://rs.fullstory.com/rec/bundle?Uid=user@example.com")
    hit = fs.parse(event)
    p = next(p for p in hit.params if p.key == "Uid")
    assert p.category == CAT_PII
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["SessionId", "PageId", "RecordingId"])
def test_other_identifiers(fs, key: str) -> None:
    event = make_request(host="rs.fullstory.com", url=f"https://rs.fullstory.com/?{key}=x")
    hit = fs.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


@pytest.mark.parametrize("key", ["OrgId", "ApiKey"])
def test_property_ids_are_technical_low(fs, key: str) -> None:
    """Org ID and API key are operator-scoped, constant across visitors — technical."""
    event = make_request(host="rs.fullstory.com", url=f"https://rs.fullstory.com/?{key}=x")
    hit = fs.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize("key", ["Channel", "EventType"])
def test_behavioral(fs, key: str) -> None:
    event = make_request(host="rs.fullstory.com", url=f"https://rs.fullstory.com/?{key}=x")
    hit = fs.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_BEHAVIORAL


@pytest.mark.parametrize("key", ["url", "PageUrl", "Referrer", "Title"])
def test_content(fs, key: str) -> None:
    event = make_request(host="rs.fullstory.com", url=f"https://rs.fullstory.com/?{key}=x")
    hit = fs.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["EventStart", "EventEnd", "Seq", "Now", "v", "fs"])
def test_technical(fs, key: str) -> None:
    event = make_request(host="rs.fullstory.com", url=f"https://rs.fullstory.com/?{key}=x")
    hit = fs.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param_falls_through(fs) -> None:
    event = make_request(host="rs.fullstory.com", url="https://rs.fullstory.com/?weird=1")
    hit = fs.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "FullStory" in p.meaning
