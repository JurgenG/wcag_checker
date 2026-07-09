"""Tests for the Azure Application Insights module."""

from __future__ import annotations

import json

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
    IMPACT_MEDIUM,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def ai():
    return module_by_id("azure_application_insights")


def test_identity(ai) -> None:
    assert ai.module_id == "azure_application_insights"
    assert ai.module_name == "Azure Application Insights"


def test_matches_visualstudio_host(ai) -> None:
    event = make_request(
        host="dc.services.visualstudio.com",
        url="https://dc.services.visualstudio.com/v2/track",
    )
    assert ai.matches(event) is True


def test_does_not_match_unrelated(ai) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert ai.matches(event) is False


def test_envelope_extracts_count_and_ikey(ai) -> None:
    body = json.dumps([
        {"iKey": "00000000-0000-0000-0000-000000000001", "tags": {}, "data": {"baseType": "PageviewData", "baseData": {"url": "https://example.com/a"}}},
        {"data": {"baseType": "PageviewData", "baseData": {"url": "https://example.com/b"}}},
    ])
    event = make_request(
        host="dc.services.visualstudio.com",
        url="https://dc.services.visualstudio.com/v2/track",
        method="POST",
        request_body=body,
    )
    hit = ai.parse(event)
    by_key = {p.key: p for p in hit.params}
    assert by_key["(body) envelope_count"].value == "2"
    assert by_key["(body) iKey"].value == "00000000-0000-0000-0000-000000000001"
    assert by_key["(body) iKey"].category == CAT_TECHNICAL
    assert by_key["(body) iKey"].privacy_impact == IMPACT_LOW


def test_envelope_telemetry_types_count(ai) -> None:
    body = json.dumps([
        {"data": {"baseType": "PageviewData", "baseData": {"url": "u1"}}},
        {"data": {"baseType": "PageviewData", "baseData": {"url": "u2"}}},
        {"data": {"baseType": "RemoteDependencyData", "baseData": {"target": "bat.bing.com"}}},
        {"data": {"baseType": "EventData", "baseData": {"name": "Purchase"}}},
    ])
    event = make_request(
        host="dc.services.visualstudio.com",
        url="https://dc.services.visualstudio.com/v2/track",
        request_body=body,
    )
    hit = ai.parse(event)
    by_key = {p.key: p for p in hit.params}
    types = by_key["(body) telemetry_types"].value
    assert "PageviewData" in types
    assert "2×" in types or "1×" in types  # at least one count present


def test_session_id_is_high_impact(ai) -> None:
    body = json.dumps([{
        "tags": {"ai.session.id": "SESSION-ABC"},
        "data": {"baseType": "PageviewData", "baseData": {"url": "https://example.com/"}},
    }])
    event = make_request(host="dc.services.visualstudio.com", url="https://dc.services.visualstudio.com/v2/track", request_body=body)
    hit = ai.parse(event)
    p = next(p for p in hit.params if p.key == "(body) ai.session.id")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


def test_undefined_user_id_drops_impact(ai) -> None:
    """When authenticated-user fields contain the literal ``undefined``, impact drops to LOW."""
    body = json.dumps([{
        "tags": {"ai.user.id": "undefined", "ai.user.authUserId": "undefined"},
        "data": {"baseType": "PageviewData", "baseData": {"url": "u"}},
    }])
    event = make_request(host="dc.services.visualstudio.com", url="https://dc.services.visualstudio.com/v2/track", request_body=body)
    hit = ai.parse(event)
    p = next(p for p in hit.params if p.key == "(body) ai.user.id")
    assert p.category == CAT_PII
    assert p.privacy_impact == IMPACT_LOW


def test_populated_user_id_is_high(ai) -> None:
    body = json.dumps([{
        "tags": {"ai.user.id": "user@example.com"},
        "data": {"baseType": "PageviewData", "baseData": {"url": "u"}},
    }])
    event = make_request(host="dc.services.visualstudio.com", url="https://dc.services.visualstudio.com/v2/track", request_body=body)
    hit = ai.parse(event)
    p = next(p for p in hit.params if p.key == "(body) ai.user.id")
    assert p.privacy_impact == IMPACT_HIGH


def test_remote_dependency_targets_surface_as_high(ai) -> None:
    body = json.dumps([
        {"data": {"baseType": "RemoteDependencyData", "baseData": {"target": "bat.bing.com"}}},
        {"data": {"baseType": "RemoteDependencyData", "baseData": {"target": "bat.bing.com"}}},
        {"data": {"baseType": "RemoteDependencyData", "baseData": {"target": "google-analytics.com"}}},
    ])
    event = make_request(host="dc.services.visualstudio.com", url="https://dc.services.visualstudio.com/v2/track", request_body=body)
    hit = ai.parse(event)
    p = next(p for p in hit.params if p.key == "(body) RemoteDependencyData.target")
    assert p.category == CAT_CONTENT
    assert p.privacy_impact == IMPACT_HIGH
    assert "bat.bing.com" in p.value


def test_event_data_names_surfaced(ai) -> None:
    body = json.dumps([
        {"data": {"baseType": "EventData", "baseData": {"name": "Purchase"}}},
        {"data": {"baseType": "EventData", "baseData": {"name": "ClickCTA"}}},
    ])
    event = make_request(host="dc.services.visualstudio.com", url="https://dc.services.visualstudio.com/v2/track", request_body=body)
    hit = ai.parse(event)
    p = next(p for p in hit.params if p.key == "(body) EventData.name")
    assert p.category == CAT_BEHAVIORAL
    assert "Purchase" in p.value


def test_invalid_body_yields_no_params(ai) -> None:
    event = make_request(host="dc.services.visualstudio.com", url="https://dc.services.visualstudio.com/v2/track", request_body="not-json")
    hit = ai.parse(event)
    assert hit.params == []


def test_empty_body_yields_no_params(ai) -> None:
    event = make_request(host="dc.services.visualstudio.com", url="https://dc.services.visualstudio.com/v2/track", request_body=None)
    hit = ai.parse(event)
    assert hit.params == []
