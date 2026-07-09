"""Tests for the HubSpot module."""

from __future__ import annotations

import json
import urllib.parse

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
def hs():
    return module_by_id("hubspot")


def test_identity(hs) -> None:
    assert hs.module_id == "hubspot"


@pytest.mark.parametrize(
    "host",
    [
        "hubspot.com", "track.hubspot.com", "forms.hubspot.com",
        "hs-scripts.com", "js.hs-scripts.com", "hs-banner.com", "hsadspixel.net",
        "hsforms.com", "cdn.hubspotusercontent.com",
    ],
)
def test_matches(hs, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert hs.matches(event) is True


def test_does_not_match_unrelated(hs) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert hs.matches(event) is False


@pytest.mark.parametrize("key", ["hubspotutk", "__hstc", "__hsfp"])
def test_persistent_identifiers_high(hs, key: str) -> None:
    event = make_request(host="track.hubspot.com", url=f"https://track.hubspot.com/__ptq.gif?{key}=ABC")
    hit = hs.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["guid", "k"])
def test_account_identifiers(hs, key: str) -> None:
    event = make_request(host="forms.hubspot.com", url=f"https://forms.hubspot.com/uploads/form?{key}=x")
    hit = hs.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


@pytest.mark.parametrize("key", ["portalId", "formId"])
def test_property_ids_are_technical(hs, key: str) -> None:
    event = make_request(host="forms.hubspot.com", url=f"https://forms.hubspot.com/uploads/form?{key}=x")
    hit = hs.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize("key", ["email", "firstname", "lastname", "phone"])
def test_pii_fields(hs, key: str) -> None:
    event = make_request(host="forms.hubspot.com", url=f"https://forms.hubspot.com/?{key}=v")
    hit = hs.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_PII


def test_v3_body_extracts_fields(hs) -> None:
    """v3 JSON body: ``{"fields": [{"name": "email", "value": "..."}, ...]}``."""
    body = json.dumps({
        "fields": [
            {"name": "email", "value": "alice@example.com"},
            {"name": "firstname", "value": "Alice"},
            {"name": "comment", "value": "I want a quote"},
        ],
        "context": {"hutk": "ABC123", "pageUri": "https://example.com/contact"},
    })
    event = make_request(
        host="forms.hubspot.com",
        url="https://forms.hubspot.com/uploads/form/v3/abc/xyz",
        method="POST",
        request_body=body,
    )
    hit = hs.parse(event)
    by_key = {p.key: p for p in hit.params}
    assert by_key["(body) field.email"].value == "alice@example.com"
    assert by_key["(body) field.email"].category == CAT_PII
    assert by_key["(body) field.firstname"].category == CAT_PII
    assert by_key["(body) field.comment"].category == CAT_PII
    assert "free-text" in by_key["(body) field.comment"].meaning.lower()
    assert by_key["(body) form_field_count"].value == "3"


def test_v3_body_context_extracts_hutk_and_uri(hs) -> None:
    body = json.dumps({
        "fields": [],
        "context": {
            "hutk": "VISITORTK",
            "pageUri": "https://example.com/contact",
            "ipAddress": "1.2.3.4",
        },
    })
    event = make_request(host="forms.hubspot.com", url="https://forms.hubspot.com/api", request_body=body)
    hit = hs.parse(event)
    by_key = {p.key: p for p in hit.params}
    assert by_key["(body) context.hutk"].category == CAT_IDENTIFIER
    assert by_key["(body) context.hutk"].privacy_impact == IMPACT_HIGH
    assert by_key["(body) context.pageUri"].category == CAT_CONTENT
    assert by_key["(body) context.ipAddress"].category == CAT_PII


def test_v3_body_legal_consent_text(hs) -> None:
    body = json.dumps({
        "fields": [],
        "legalConsentOptions": {"consent": {"text": "I agree to receive marketing emails"}},
    })
    event = make_request(host="forms.hubspot.com", url="https://forms.hubspot.com/", request_body=body)
    hit = hs.parse(event)
    p = next(p for p in hit.params if p.key == "(body) legal.consent_text")
    assert p.category == CAT_CONSENT


def test_hs_context_form_encoded_extracts_hutk(hs) -> None:
    """The older form-encoded transport encodes context as URL-encoded JSON in ``hs_context``."""
    ctx = {"hutk": "OLDFORMUTK", "pageUri": "https://example.com/old-form"}
    hs_context = urllib.parse.quote(json.dumps(ctx))
    event = make_request(
        host="forms.hubspot.com",
        url=f"https://forms.hubspot.com/uploads/form/v2/abc/xyz?hs_context={hs_context}",
    )
    hit = hs.parse(event)
    by_key = {p.key: p for p in hit.params}
    # The raw query param appears AND the decoded context.hutk does.
    assert by_key["(body) context.hutk"].value == "OLDFORMUTK"


def test_v3_body_pii_address_fields_via_keyword(hs) -> None:
    body = json.dumps({"fields": [{"name": "street_address", "value": "123 Main St"}]})
    event = make_request(host="forms.hubspot.com", url="https://forms.hubspot.com/api", request_body=body)
    hit = hs.parse(event)
    p = next(p for p in hit.params if p.key == "(body) field.street_address")
    assert p.category == CAT_PII


def test_v3_body_hs_internal_fields_technical(hs) -> None:
    body = json.dumps({"fields": [{"name": "hs_lead_status", "value": "warm"}]})
    event = make_request(host="forms.hubspot.com", url="https://forms.hubspot.com/api", request_body=body)
    hit = hs.parse(event)
    p = next(p for p in hit.params if p.key == "(body) field.hs_lead_status")
    assert p.category == CAT_TECHNICAL


def test_v3_body_handles_invalid_json(hs) -> None:
    event = make_request(host="forms.hubspot.com", url="https://forms.hubspot.com/api", request_body="not-json")
    hit = hs.parse(event)
    assert not any(p.key.startswith("(body) field.") for p in hit.params)


def test_unknown_param(hs) -> None:
    event = make_request(host="forms.hubspot.com", url="https://forms.hubspot.com/?weird=1")
    hit = hs.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "HubSpot" in p.meaning
