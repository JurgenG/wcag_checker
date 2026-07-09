"""Tests for the Microsoft Clarity module."""

from __future__ import annotations

import json

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_HIGH,
    IMPACT_LOW,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def cl():
    return module_by_id("clarity")


def test_identity(cl) -> None:
    assert cl.module_id == "clarity"
    assert cl.module_name == "Microsoft Clarity"


@pytest.mark.parametrize(
    "host", ["clarity.ms", "scripts.clarity.ms", "www.clarity.ms", "c.clarity.ms", "x.clarity.ms"],
)
def test_matches(cl, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert cl.matches(event) is True


def test_does_not_match_unrelated(cl) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert cl.matches(event) is False


def test_path_extracts_project_id(cl) -> None:
    event = make_request(
        host="www.clarity.ms",
        url="https://www.clarity.ms/tag/ABC123XYZ",
    )
    hit = cl.parse(event)
    p = next(p for p in hit.params if p.key == "(path) project_id")
    assert p.value == "ABC123XYZ"
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


def test_envelope_extracts_user_session_project_ids(cl) -> None:
    """Clarity ``/collect`` POSTs carry an ``e`` array with identifying fields."""
    body = json.dumps({
        "e": [
            "0.8.5",          # 0 script_version
            "platform",       # 1 (unused)
            "extra",           # 2 (unused)
            "extra",           # 3 (unused)
            "PROJ123",         # 4 project_id
            "USER123",         # 5 user_id
            "SESSION456",      # 6 session_id
            "x", "x", "x", "x",  # 7-10 (unused)
            "https://example.com/page",  # 11 page_url
        ],
        "a": [["t1", "click"], ["t2", "scroll"]],
    })
    event = make_request(
        host="c.clarity.ms",
        url="https://c.clarity.ms/collect",
        method="POST",
        request_body=body,
    )
    hit = cl.parse(event)
    by_key = {p.key: p for p in hit.params}
    assert by_key["(body) script_version"].value == "0.8.5"
    assert by_key["(body) project_id"].value == "PROJ123"
    assert by_key["(body) project_id"].category == CAT_TECHNICAL
    assert by_key["(body) project_id"].privacy_impact == IMPACT_LOW
    assert by_key["(body) user_id"].value == "USER123"
    assert by_key["(body) user_id"].privacy_impact == IMPACT_HIGH
    assert by_key["(body) session_id"].value == "SESSION456"
    assert by_key["(body) page_url"].value == "https://example.com/page"
    assert by_key["(body) action_count"].value == "2"
    assert by_key["(body) action_count"].category == CAT_BEHAVIORAL
    assert by_key["(body) action_count"].privacy_impact == IMPACT_HIGH


def test_envelope_handles_invalid_body(cl) -> None:
    event = make_request(host="c.clarity.ms", url="https://c.clarity.ms/collect", request_body="not-json")
    hit = cl.parse(event)
    # No envelope params — gracefully skipped.
    assert not any(p.key.startswith("(body)") for p in hit.params)


def test_envelope_handles_wrong_shape(cl) -> None:
    """If position 0 isn't a version-shaped string, skip envelope extraction."""
    body = json.dumps({"e": [123, "wrong-shape"]})
    event = make_request(host="c.clarity.ms", url="https://c.clarity.ms/collect", request_body=body)
    hit = cl.parse(event)
    # Action count would still be emitted if 'a' present; but envelope fields skipped.
    assert not any(p.key == "(body) script_version" for p in hit.params)


@pytest.mark.parametrize("key", ["uid", "sid", "tid", "pn"])
def test_identifiers(cl, key: str) -> None:
    event = make_request(host="c.clarity.ms", url=f"https://c.clarity.ms/collect?{key}=x")
    hit = cl.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


def test_pid_is_technical_low(cl) -> None:
    """``pid`` is the operator-scoped Clarity project ID — technical, low impact."""
    event = make_request(host="c.clarity.ms", url="https://c.clarity.ms/collect?pid=x")
    hit = cl.parse(event)
    p = next(p for p in hit.params if p.key == "pid")
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


def test_upload_is_behavioral_high(cl) -> None:
    event = make_request(host="c.clarity.ms", url="https://c.clarity.ms/collect?upload=blob")
    hit = cl.parse(event)
    p = next(p for p in hit.params if p.key == "upload")
    assert p.category == CAT_BEHAVIORAL
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["url", "ref", "title"])
def test_content(cl, key: str) -> None:
    event = make_request(host="c.clarity.ms", url=f"https://c.clarity.ms/collect?{key}=x")
    hit = cl.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["v", "seq", "ts", "insights"])
def test_technical(cl, key: str) -> None:
    event = make_request(host="c.clarity.ms", url=f"https://c.clarity.ms/collect?{key}=x")
    hit = cl.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param(cl) -> None:
    event = make_request(host="c.clarity.ms", url="https://c.clarity.ms/?weird=1")
    hit = cl.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Clarity" in p.meaning
