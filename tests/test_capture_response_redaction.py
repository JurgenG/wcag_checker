"""Tests for schema-preserving redaction of captured response bodies.

Capture stores response bodies for forensic drill-down, but a response
body is the place the visitor's *own* data comes back (logged-in account
JSON, profile fields). To keep the bundle — a shareable artifact — free
of that PII while still recording *what* an endpoint returns, capture
redacts response bodies at write time:

* JSON responses keep their field names and value *types* but every
  scalar value is replaced with a type-appropriate placeholder
  (``"XXXXXXX"`` / ``0`` / ``false``; ``null`` stays ``null``). Object
  keys and array lengths are preserved.
* Non-JSON responses (HTML, binary, unknown content-type) are dropped
  entirely — they have no clean key/value shape to preserve, so storing
  them would only risk leaking PII.
* Request bodies are never touched: they are the outbound-leak evidence
  and the core of the analysis.
"""

from __future__ import annotations

import json

from leak_inspector.capture.bidi import (
    _normalize_request,
    _redact_json_body,
    _redact_response_body,
)


# --- pure JSON redaction ----------------------------------------------------


def test_redact_json_replaces_scalars_by_type() -> None:
    body = json.dumps({"email": "a@b.com", "balance": 42.5,
                        "count": 7, "verified": True, "deleted_at": None})
    out = json.loads(_redact_json_body(body))
    assert out == {"email": "XXXXXXX", "balance": 0,
                   "count": 0, "verified": False, "deleted_at": None}


def test_redact_json_preserves_keys_and_nesting() -> None:
    body = json.dumps({"user": {"name": "Jane", "tags": ["vip", "eu"]}})
    out = json.loads(_redact_json_body(body))
    assert out == {"user": {"name": "XXXXXXX",
                            "tags": ["XXXXXXX", "XXXXXXX"]}}


def test_redact_json_preserves_array_length() -> None:
    body = json.dumps({"tx": [{"id": 1}, {"id": 2}, {"id": 3}]})
    out = json.loads(_redact_json_body(body))
    assert out == {"tx": [{"id": 0}, {"id": 0}, {"id": 0}]}
    assert len(out["tx"]) == 3


def test_redact_json_top_level_array() -> None:
    out = json.loads(_redact_json_body(json.dumps(["x@y.com", "z@w.com"])))
    assert out == ["XXXXXXX", "XXXXXXX"]


def test_redact_json_bool_is_not_treated_as_number() -> None:
    # bool is a subclass of int in Python — must stay a bool, not become 0.
    out = json.loads(_redact_json_body(json.dumps({"flag": True})))
    assert out["flag"] is False


def test_redact_json_invalid_body_fails_closed() -> None:
    # Truncated / non-JSON content (e.g. a body cut at the 256 KB cap)
    # must be dropped, never stored raw.
    assert _redact_json_body('{"email": "a@b.com", "trunc') is None
    assert _redact_json_body("<html>not json</html>") is None


# --- content-type gating ----------------------------------------------------


def test_redact_response_body_redacts_json_mimes() -> None:
    body = json.dumps({"email": "a@b.com"})
    for mime in ("application/json",
                 "application/json; charset=utf-8",
                 "application/ld+json",
                 "text/json"):
        out = _redact_response_body(body, mime)
        assert json.loads(out) == {"email": "XXXXXXX"}, mime


def test_redact_response_body_drops_non_json() -> None:
    assert _redact_response_body("<html>secret</html>", "text/html") is None
    assert _redact_response_body('{"email":"a@b.com"}', None) is None
    assert _redact_response_body(None, "application/json") is None


# --- integration through _normalize_request ---------------------------------


def _normalize(mime: str, response_body: str, request_body: str):
    return _normalize_request(
        event_id=1,
        bidi_request_data={"method": "POST",
                           "url": "https://site.example/api/me",
                           "headers": []},
        bidi_response_data={"status": 200, "mimeType": mime, "headers": []},
        context="ctx", timestamp_ms=0, initiator=None,
        request_body=request_body, response_body=response_body,
    )["payload"]


def test_normalize_request_redacts_json_response_keeps_request_body() -> None:
    payload = _normalize(
        "application/json",
        response_body=json.dumps({"email": "a@b.com", "n": 5}),
        request_body=json.dumps({"q": "search-term"}),
    )
    # Request body is the leak evidence — untouched.
    assert payload["request_body"] == json.dumps({"q": "search-term"})
    # Response body keeps shape, loses values.
    assert json.loads(payload["response_body"]) == {"email": "XXXXXXX", "n": 0}


def test_normalize_request_drops_html_response_body() -> None:
    payload = _normalize(
        "text/html",
        response_body="<html><body>account: a@b.com</body></html>",
        request_body="q=x",
    )
    assert payload["response_body"] is None
    assert payload["request_body"] == "q=x"
    # The mime is still recorded so the bundle shows a response existed.
    assert payload["response_mime"] == "text/html"
