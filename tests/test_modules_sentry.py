"""Tests for the Sentry module."""

from __future__ import annotations

import json

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
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def s():
    return module_by_id("sentry")


def test_identity(s) -> None:
    assert s.module_id == "sentry"


def test_matches_hosted_sentry(s) -> None:
    event = make_request(
        host="o123.ingest.sentry.io",
        url="https://o123.ingest.sentry.io/api/456/envelope/",
    )
    assert s.matches(event) is True


def test_does_not_match_sentry_marketing(s) -> None:
    """``sentry.io`` paths outside ``/api/`` (docs, marketing) are NOT claimed."""
    event = make_request(host="sentry.io", url="https://sentry.io/welcome")
    assert s.matches(event) is False


def test_matches_sdk_cdn_host(s) -> None:
    """``*.sentry-cdn.com`` serves the Sentry browser SDK into the origin."""
    event = make_request(
        host="browser.sentry-cdn.com",
        url="https://browser.sentry-cdn.com/7.120.3/bundle.min.js",
    )
    assert s.matches(event) is True


def test_matches_self_hosted_via_dsn_params(s) -> None:
    """Self-hosted Sentry → ``sentry_key`` + ``sentry_version`` in the query string."""
    event = make_request(
        host="errors.example.com",
        url="https://errors.example.com/api/store/?sentry_key=ABC&sentry_version=7",
    )
    assert s.matches(event) is True


def test_does_not_match_unrelated(s) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert s.matches(event) is False


def test_envelope_extracts_user_email(s) -> None:
    body = json.dumps({"user": {"email": "alice@example.com"}})
    event = make_request(
        host="o1.ingest.sentry.io",
        url="https://o1.ingest.sentry.io/api/1/envelope/",
        method="POST",
        request_body=body,
    )
    hit = s.parse(event)
    p = next(p for p in hit.params if p.key == "(body) user.email")
    assert p.value == "alice@example.com"
    assert p.category == CAT_PII
    assert p.privacy_impact == IMPACT_HIGH


def test_envelope_extracts_exception(s) -> None:
    body = json.dumps({
        "exception": {"values": [{
            "type": "TypeError",
            "value": "Cannot read properties of undefined (reading 'foo')",
            "stacktrace": {"frames": [{}, {}, {}, {}, {}]},
        }]},
    })
    event = make_request(host="o1.ingest.sentry.io", url="https://o1.ingest.sentry.io/api/1/envelope/", request_body=body)
    hit = s.parse(event)
    by_key = {p.key: p for p in hit.params}
    assert by_key["(body) exception.type"].value == "TypeError"
    assert by_key["(body) exception.type"].category == CAT_BEHAVIORAL
    assert by_key["(body) exception.message"].category == CAT_PII
    assert "Cannot read properties" in by_key["(body) exception.message"].value
    assert by_key["(body) stack_depth"].value == "5"


def test_envelope_extracts_breadcrumbs_count(s) -> None:
    body = json.dumps({
        "breadcrumbs": {"values": [{"category": "navigation"}, {"category": "ui.click"}]},
    })
    event = make_request(host="o1.ingest.sentry.io", url="https://o1.ingest.sentry.io/api/1/envelope/", request_body=body)
    hit = s.parse(event)
    p = next(p for p in hit.params if p.key == "(body) breadcrumb_count")
    assert p.value == "2"
    assert p.category == CAT_BEHAVIORAL
    assert p.privacy_impact == IMPACT_HIGH


def test_envelope_extracts_request_url(s) -> None:
    body = json.dumps({"request": {"url": "https://example.com/checkout"}})
    event = make_request(host="o1.ingest.sentry.io", url="https://o1.ingest.sentry.io/api/1/envelope/", request_body=body)
    hit = s.parse(event)
    p = next(p for p in hit.params if p.key == "(body) request.url")
    assert p.category == CAT_CONTENT
    assert p.value == "https://example.com/checkout"


def test_envelope_extracts_transaction(s) -> None:
    body = json.dumps({"transaction": "/api/checkout"})
    event = make_request(host="o1.ingest.sentry.io", url="https://o1.ingest.sentry.io/api/1/envelope/", request_body=body)
    hit = s.parse(event)
    p = next(p for p in hit.params if p.key == "(body) transaction")
    assert p.category == CAT_BEHAVIORAL


def test_envelope_lists_tag_keys(s) -> None:
    body = json.dumps({"tags": {"region": "eu", "feature_flag_x": "on", "color": "red"}})
    event = make_request(host="o1.ingest.sentry.io", url="https://o1.ingest.sentry.io/api/1/envelope/", request_body=body)
    hit = s.parse(event)
    p = next(p for p in hit.params if p.key == "(body) tags")
    assert "3 tag(s)" in p.value


def test_envelope_handles_newline_delimited(s) -> None:
    """Sentry envelopes are newline-delimited JSON."""
    body = (
        json.dumps({"event_id": "abc"}) + "\n"
        + json.dumps({"user": {"email": "u@example.com"}}) + "\n"
    )
    event = make_request(host="o1.ingest.sentry.io", url="https://o1.ingest.sentry.io/api/1/envelope/", request_body=body)
    hit = s.parse(event)
    assert any(p.key == "(body) user.email" for p in hit.params)


def test_envelope_handles_invalid_lines(s) -> None:
    """Lines that aren't valid JSON are skipped, valid ones still surface."""
    body = "garbage\n" + json.dumps({"user": {"id": "USR1"}}) + "\n"
    event = make_request(host="o1.ingest.sentry.io", url="https://o1.ingest.sentry.io/api/1/envelope/", request_body=body)
    hit = s.parse(event)
    p = next(p for p in hit.params if p.key == "(body) user.id")
    assert p.value == "USR1"


@pytest.mark.parametrize("key", ["sentry_key", "sentry_secret"])
def test_dsn_keys_are_identifiers(s, key: str) -> None:
    event = make_request(
        host="errors.example.com",
        url=f"https://errors.example.com/api/store/?{key}=ABC&sentry_version=7",
    )
    hit = s.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param(s) -> None:
    event = make_request(
        host="o1.ingest.sentry.io",
        url="https://o1.ingest.sentry.io/api/1/envelope/?weird=1",
    )
    hit = s.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
