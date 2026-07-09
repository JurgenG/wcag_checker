"""Tests for the Mailjet module."""

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
def mj():
    return module_by_id("mailjet")


def test_identity(mj) -> None:
    assert mj.module_id == "mailjet"
    assert mj.module_name == "Mailjet"
    assert mj.legal_jurisdiction == "SE"


@pytest.mark.parametrize(
    "host",
    ["mailjet.com", "mjt.lu", "mailjet.net", "app.mailjet.com", "links.mjt.lu"],
)
def test_matches(mj, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert mj.matches(event) is True


def test_email_is_pii_high(mj) -> None:
    event = make_request(host="app.mailjet.com", url="https://app.mailjet.com/?email=u@example.com")
    hit = mj.parse(event)
    p = next(p for p in hit.params if p.key == "email")
    assert p.category == CAT_PII
    assert p.privacy_impact == IMPACT_HIGH


def test_contactid_is_high_impact(mj) -> None:
    event = make_request(host="app.mailjet.com", url="https://app.mailjet.com/?contactid=ABC")
    hit = mj.parse(event)
    p = next(p for p in hit.params if p.key == "contactid")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["widget", "wid", "listid", "userid", "campaign"])
def test_property_ids_are_technical(mj, key: str) -> None:
    event = make_request(host="app.mailjet.com", url=f"https://app.mailjet.com/?{key}=x")
    hit = mj.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize("key", ["firstname", "lastname", "name", "phone"])
def test_pii_fields(mj, key: str) -> None:
    event = make_request(host="app.mailjet.com", url=f"https://app.mailjet.com/?{key}=x")
    hit = mj.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_PII


def test_type_is_behavioral(mj) -> None:
    event = make_request(host="app.mailjet.com", url="https://app.mailjet.com/?type=open")
    hit = mj.parse(event)
    p = next(p for p in hit.params if p.key == "type")
    assert p.category == CAT_BEHAVIORAL


def test_url_is_content(mj) -> None:
    event = make_request(host="app.mailjet.com", url="https://app.mailjet.com/?url=https://x")
    hit = mj.parse(event)
    p = next(p for p in hit.params if p.key == "url")
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["v", "callback", "r"])
def test_technical(mj, key: str) -> None:
    event = make_request(host="app.mailjet.com", url=f"https://app.mailjet.com/?{key}=x")
    hit = mj.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param(mj) -> None:
    event = make_request(host="app.mailjet.com", url="https://app.mailjet.com/?weird=1")
    hit = mj.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Mailjet" in p.meaning
