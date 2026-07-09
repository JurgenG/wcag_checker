"""Tests for the Zendesk module."""

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
def zd():
    return module_by_id("zendesk")


def test_identity(zd) -> None:
    assert zd.module_id == "zendesk"
    assert zd.module_name == "Zendesk Widget"


@pytest.mark.parametrize(
    "host",
    [
        "static.zdassets.com",
        "ekr.zdassets.com",
        "acme.zendesk.com",
        "old.zopim.com",
    ],
)
def test_matches(zd, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert zd.matches(event) is True


def test_does_not_match_unrelated(zd) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert zd.matches(event) is False


@pytest.mark.parametrize("key", ["key", "accountKey", "subdomain", "embedKey", "embed"])
def test_property_ids_are_technical(zd, key: str) -> None:
    event = make_request(host="static.zdassets.com", url=f"https://static.zdassets.com/?{key}=x")
    hit = zd.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize(
    "key", ["name", "email", "phone", "external_id", "msg", "subject", "description"],
)
def test_pii_fields(zd, key: str) -> None:
    event = make_request(host="acme.zendesk.com", url=f"https://acme.zendesk.com/?{key}=x")
    hit = zd.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_PII
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["event", "action", "rating"])
def test_behavioral(zd, key: str) -> None:
    event = make_request(host="acme.zendesk.com", url=f"https://acme.zendesk.com/?{key}=x")
    hit = zd.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_BEHAVIORAL


@pytest.mark.parametrize("key", ["url", "referrer", "title"])
def test_content(zd, key: str) -> None:
    event = make_request(host="acme.zendesk.com", url=f"https://acme.zendesk.com/?{key}=x")
    hit = zd.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["widgetVersion", "version", "locale", "channel", "type"])
def test_technical(zd, key: str) -> None:
    event = make_request(host="acme.zendesk.com", url=f"https://acme.zendesk.com/?{key}=x")
    hit = zd.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param(zd) -> None:
    event = make_request(host="acme.zendesk.com", url="https://acme.zendesk.com/?weird=1")
    hit = zd.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Zendesk" in p.meaning
