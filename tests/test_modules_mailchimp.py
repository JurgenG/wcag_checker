"""Tests for the Mailchimp module."""

from __future__ import annotations

import json

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_PII,
    CAT_TECHNICAL,
    IMPACT_HIGH,
    IMPACT_LOW,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def mc():
    return module_by_id("mailchimp")


def test_identity(mc) -> None:
    assert mc.module_id == "mailchimp"
    assert mc.module_name == "Mailchimp"


@pytest.mark.parametrize(
    "host",
    ["list-manage.com", "us1.list-manage.com", "mailchimp.com", "chimpstatic.com"],
)
def test_matches(mc, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert mc.matches(event) is True


def test_does_not_match_unrelated(mc) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert mc.matches(event) is False


@pytest.mark.parametrize("key", ["EMAIL", "FNAME", "LNAME", "PHONE", "BIRTHDAY"])
def test_pii_fields(mc, key: str) -> None:
    event = make_request(host="us1.list-manage.com", url=f"https://us1.list-manage.com/subscribe/post?{key}=value")
    hit = mc.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_PII
    assert p.privacy_impact == IMPACT_HIGH


def test_mmerge_numeric_is_pii(mc) -> None:
    """``MMERGE3`` → CAT_PII, meaning mentions slot 3."""
    event = make_request(host="us1.list-manage.com", url="https://us1.list-manage.com/?MMERGE3=premium")
    hit = mc.parse(event)
    p = next(p for p in hit.params if p.key == "MMERGE3")
    assert p.category == CAT_PII
    assert "3" in p.meaning


def test_group_selection_is_behavioral(mc) -> None:
    event = make_request(host="us1.list-manage.com", url="https://us1.list-manage.com/?group[5]=on")
    hit = mc.parse(event)
    p = next(p for p in hit.params if p.key == "group[5]")
    assert p.category == CAT_BEHAVIORAL
    assert "5" in p.meaning


def test_group_with_choice_index(mc) -> None:
    event = make_request(host="us1.list-manage.com", url="https://us1.list-manage.com/?group[5][1]=on")
    hit = mc.parse(event)
    p = next(p for p in hit.params if p.key == "group[5][1]")
    assert p.category == CAT_BEHAVIORAL


def test_honeypot_is_technical(mc) -> None:
    """``b_<userid>_<listid>`` is the anti-bot honeypot — TECHNICAL, not PII."""
    event = make_request(host="us1.list-manage.com", url="https://us1.list-manage.com/?b_abc123_def456=")
    hit = mc.parse(event)
    p = next(p for p in hit.params if p.key == "b_abc123_def456")
    assert p.category == CAT_TECHNICAL


def test_e_is_high_impact(mc) -> None:
    """``e`` is the email-hash identifier on open-tracking URLs."""
    event = make_request(host="us1.list-manage.com", url="https://us1.list-manage.com/?e=ABC")
    hit = mc.parse(event)
    p = next(p for p in hit.params if p.key == "e")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["uniqid"])
def test_identifiers(mc, key: str) -> None:
    event = make_request(host="us1.list-manage.com", url=f"https://us1.list-manage.com/?{key}=x")
    hit = mc.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


@pytest.mark.parametrize("key", ["u", "id", "f_id"])
def test_property_ids_are_technical(mc, key: str) -> None:
    event = make_request(host="us1.list-manage.com", url=f"https://us1.list-manage.com/?{key}=x")
    hit = mc.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


def test_v3_body_extracts_email_and_merge(mc) -> None:
    """v3 JSON body shape: top-level ``email_address`` + ``merge_fields``."""
    body = json.dumps({
        "email_address": "user@example.com",
        "status": "subscribed",
        "merge_fields": {"FNAME": "Alice", "LNAME": "Smith"},
        "tags": ["lead"],
        "ip_signup": "1.2.3.4",
    })
    event = make_request(
        host="us1.list-manage.com",
        url="https://us1.list-manage.com/api/v3/lists/abc/members",
        method="POST",
        request_body=body,
    )
    hit = mc.parse(event)
    by_key = {p.key: p for p in hit.params}
    assert by_key["(body) email_address"].value == "user@example.com"
    assert by_key["(body) email_address"].category == CAT_PII
    assert by_key["(body) status"].value == "subscribed"
    assert by_key["(body) status"].category == CAT_BEHAVIORAL
    assert by_key["(body) ip_signup"].category == CAT_PII
    assert by_key["(body) merge_fields.FNAME"].value == "Alice"
    assert by_key["(body) merge_fields.FNAME"].category == CAT_PII
    assert by_key["(body) tags"].category == CAT_BEHAVIORAL


def test_v3_body_skips_when_no_email_address(mc) -> None:
    body = json.dumps({"other": "stuff"})
    event = make_request(host="us1.list-manage.com", url="https://us1.list-manage.com/api", request_body=body)
    hit = mc.parse(event)
    assert not any(p.key.startswith("(body)") for p in hit.params)


def test_invalid_json_body_handled(mc) -> None:
    event = make_request(host="us1.list-manage.com", url="https://us1.list-manage.com/api", request_body="not-json")
    hit = mc.parse(event)
    assert not any(p.key.startswith("(body)") for p in hit.params)


def test_unknown_param(mc) -> None:
    event = make_request(host="us1.list-manage.com", url="https://us1.list-manage.com/?weirdo=1")
    hit = mc.parse(event)
    p = next(p for p in hit.params if p.key == "weirdo")
    assert p.category == CAT_OTHER
    assert "Mailchimp" in p.meaning
