"""Tests for the Hotjar module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
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
def hj():
    return module_by_id("hotjar")


def test_identity(hj) -> None:
    assert hj.module_id == "hotjar"
    assert hj.module_name == "Hotjar"
    assert hj.legal_jurisdiction == "FR"  # acquired by Contentsquare


@pytest.mark.parametrize(
    "host", ["hotjar.com", "static.hotjar.com", "hotjar.io", "insights.hotjar.com"],
)
def test_matches(hj, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert hj.matches(event) is True


def test_user_id_is_high(hj) -> None:
    event = make_request(host="insights.hotjar.com", url="https://insights.hotjar.com/?user_id=ABC")
    hit = hj.parse(event)
    p = next(p for p in hit.params if p.key == "user_id")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


def test_uid_is_pii(hj) -> None:
    """Site-supplied Identify-API uid is PII."""
    event = make_request(host="identify.hotjar.com", url="https://identify.hotjar.com/?uid=user@example.com")
    hit = hj.parse(event)
    p = next(p for p in hit.params if p.key == "uid")
    assert p.category == CAT_PII


@pytest.mark.parametrize("key", ["visit_id", "session_id", "recording_id"])
def test_identifiers(hj, key: str) -> None:
    event = make_request(host="insights.hotjar.com", url=f"https://insights.hotjar.com/?{key}=x")
    hit = hj.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


@pytest.mark.parametrize("key", ["hjid", "site_id", "survey_id", "feedback_id"])
def test_property_ids_are_technical_low(hj, key: str) -> None:
    """Property/operator-scoped Hotjar IDs are constant across visitors — technical."""
    event = make_request(host="insights.hotjar.com", url=f"https://insights.hotjar.com/?{key}=x")
    hit = hj.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize("key", ["events", "user_interaction", "actions"])
def test_replay_payload_is_behavioral_high(hj, key: str) -> None:
    event = make_request(host="insights.hotjar.com", url=f"https://insights.hotjar.com/?{key}=x")
    hit = hj.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_BEHAVIORAL
    assert p.privacy_impact == IMPACT_HIGH


def test_answers_is_pii(hj) -> None:
    event = make_request(host="surveys.hotjar.com", url="https://surveys.hotjar.com/?answers=text")
    hit = hj.parse(event)
    p = next(p for p in hit.params if p.key == "answers")
    assert p.category == CAT_PII


@pytest.mark.parametrize("key", ["url", "page_url", "referrer", "page_title"])
def test_content(hj, key: str) -> None:
    event = make_request(host="insights.hotjar.com", url=f"https://insights.hotjar.com/?{key}=x")
    hit = hj.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["consent", "gdpr_consent"])
def test_consent(hj, key: str) -> None:
    event = make_request(host="insights.hotjar.com", url=f"https://insights.hotjar.com/?{key}=1")
    hit = hj.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


@pytest.mark.parametrize("key", ["sv", "hjsv", "v", "r", "ts", "seq"])
def test_technical(hj, key: str) -> None:
    event = make_request(host="insights.hotjar.com", url=f"https://insights.hotjar.com/?{key}=x")
    hit = hj.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param(hj) -> None:
    event = make_request(host="insights.hotjar.com", url="https://insights.hotjar.com/?weird=1")
    hit = hj.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Hotjar" in p.meaning
