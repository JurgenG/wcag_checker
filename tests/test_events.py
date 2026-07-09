"""Tests for ``leak_inspector.events`` — normalized event dataclasses.

Covers the 29 spec rules confirmed before deleting the implementation:

* A (1-2): TYPE_* discriminator constants.
* B (3): EventParseError is a ValueError subclass.
* C (4): Event base dataclass shape.
* D (5-10): Typed subclass shapes.
* E (11-14): RequestEvent.query_params.
* F (15-19): RequestEvent.body_params (content-type case-insensitive).
* G (20): RequestEvent.all_params (body wins).
* H (21-26): parse_event dispatch + forward-compat payload.
* I (27-29): serialize_event base-only output and round-trip.
"""

from __future__ import annotations

import pytest

from leak_inspector.events import (
    Event,
    EventParseError,
    LogEvent,
    NavigationEvent,
    RequestEvent,
    ScriptLoadEvent,
    StorageSnapshotEvent,
    TYPE_LOG,
    TYPE_NAVIGATION,
    TYPE_REQUEST,
    TYPE_SCRIPT_LOAD,
    TYPE_STORAGE_SNAPSHOT,
    TYPE_WEBSOCKET_CLOSE,
    TYPE_WEBSOCKET_MESSAGE,
    TYPE_WEBSOCKET_OPEN,
    WebSocketEvent,
    parse_event,
    serialize_event,
)


# --- A. type discriminator constants ----------------------------------------


@pytest.mark.parametrize(
    ("constant", "expected"),
    [
        (TYPE_NAVIGATION, "navigation"),
        (TYPE_REQUEST, "request"),
        (TYPE_WEBSOCKET_OPEN, "websocket_open"),
        (TYPE_WEBSOCKET_MESSAGE, "websocket_message"),
        (TYPE_WEBSOCKET_CLOSE, "websocket_close"),
        (TYPE_STORAGE_SNAPSHOT, "storage_snapshot"),
        (TYPE_SCRIPT_LOAD, "script_load"),
        (TYPE_LOG, "log"),
    ],
)
def test_type_constant_values(constant: str, expected: str) -> None:
    assert constant == expected


# --- B. exception class -----------------------------------------------------


def test_event_parse_error_subclasses_value_error() -> None:
    assert issubclass(EventParseError, ValueError)


# --- C. Event base dataclass ------------------------------------------------


def test_event_required_positional_fields() -> None:
    e = Event(
        event_id=7,
        timestamp="2026-05-01T00:00:00Z",
        type="log",
        context_id="ctx-1",
        payload={"x": 1},
    )
    assert e.event_id == 7
    assert e.timestamp == "2026-05-01T00:00:00Z"
    assert e.type == "log"
    assert e.context_id == "ctx-1"
    assert e.payload == {"x": 1}


def test_event_context_id_can_be_none() -> None:
    e = Event(event_id=1, timestamp="t", type="log", context_id=None, payload={})
    assert e.context_id is None


# --- D. typed subclasses ----------------------------------------------------


def _base_kwargs(event_type: str = "log") -> dict:
    return {
        "event_id": 1,
        "timestamp": "2026-05-01T00:00:00Z",
        "type": event_type,
        "context_id": None,
        "payload": {},
    }


def test_navigation_event_adds_url() -> None:
    e = NavigationEvent(**_base_kwargs("navigation"), url="https://example.com/")
    assert e.url == "https://example.com/"
    assert isinstance(e, Event)


def test_request_event_full_construction() -> None:
    e = RequestEvent(
        **_base_kwargs("request"),
        method="POST",
        url="https://x.example/a?b=1",
        host="x.example",
        headers={"Content-Type": "text/plain"},
        request_body="hello",
        initiator="script",
        response_status=200,
        response_mime="text/plain",
        response_headers={"Server": "nginx"},
    )
    assert e.method == "POST"
    assert e.host == "x.example"
    assert e.headers == {"Content-Type": "text/plain"}
    assert e.request_body == "hello"
    assert e.initiator == "script"
    assert e.response_status == 200
    assert e.response_mime == "text/plain"
    assert e.response_headers == {"Server": "nginx"}
    assert e.response_body is None  # default


def test_request_event_response_body_default_is_none() -> None:
    e = RequestEvent(
        **_base_kwargs("request"),
        method="GET", url="", host="", headers={}, request_body=None,
        initiator=None, response_status=None, response_mime=None,
        response_headers={},
    )
    assert e.response_body is None


def test_storage_snapshot_event_fields() -> None:
    e = StorageSnapshotEvent(
        **_base_kwargs("storage_snapshot"),
        origin="https://example.com",
        kind="localStorage",
        entries=[{"key": "k", "value": "v"}],
    )
    assert e.origin == "https://example.com"
    assert e.kind == "localStorage"
    assert e.entries == [{"key": "k", "value": "v"}]


def test_script_load_event_fields() -> None:
    e = ScriptLoadEvent(
        **_base_kwargs("script_load"),
        url="https://example.com/a.js",
        sha256="abc123",
    )
    assert e.url == "https://example.com/a.js"
    assert e.sha256 == "abc123"


def test_log_event_fields() -> None:
    e = LogEvent(**_base_kwargs("log"), level="error", text="boom")
    assert e.level == "error"
    assert e.text == "boom"


def test_websocket_event_all_fields_nullable() -> None:
    e = WebSocketEvent(
        **_base_kwargs("websocket_open"),
        url=None, data=None, direction=None, code=None, reason=None,
    )
    assert e.url is None
    assert e.data is None
    assert e.direction is None
    assert e.code is None
    assert e.reason is None


# --- E. RequestEvent.query_params -------------------------------------------


def _req(
    url: str = "",
    request_body: str | None = None,
    headers: dict[str, str] | None = None,
) -> RequestEvent:
    return RequestEvent(
        **_base_kwargs("request"),
        method="GET",
        url=url,
        host="",
        headers=headers or {},
        request_body=request_body,
        initiator=None,
        response_status=None,
        response_mime=None,
        response_headers={},
    )


def test_query_params_parses_url() -> None:
    e = _req(url="https://example.com/p?a=1&b=2")
    assert e.query_params == {"a": "1", "b": "2"}


def test_query_params_empty_when_no_query() -> None:
    e = _req(url="https://example.com/p")
    assert e.query_params == {}


def test_query_params_keep_blank_values() -> None:
    e = _req(url="https://example.com/p?a=")
    assert e.query_params == {"a": ""}


def test_query_params_repeated_key_collapses_to_last() -> None:
    e = _req(url="https://example.com/p?a=1&a=2")
    assert e.query_params == {"a": "2"}


def test_query_params_returns_fresh_dict() -> None:
    e = _req(url="https://example.com/p?a=1")
    first = e.query_params
    first["mutated"] = "yes"
    assert e.query_params == {"a": "1"}


# --- F. RequestEvent.body_params --------------------------------------------


def test_body_params_empty_when_body_falsy() -> None:
    assert _req(request_body=None).body_params == {}
    assert _req(request_body="").body_params == {}


def test_body_params_empty_when_no_content_type_header() -> None:
    e = _req(request_body="a=1&b=2", headers={})
    assert e.body_params == {}


def test_body_params_empty_when_content_type_is_not_form_urlencoded() -> None:
    e = _req(
        request_body='{"a":1}',
        headers={"Content-Type": "application/json"},
    )
    assert e.body_params == {}


def test_body_params_parses_form_urlencoded() -> None:
    e = _req(
        request_body="a=1&b=2",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert e.body_params == {"a": "1", "b": "2"}


def test_body_params_keep_blank_values() -> None:
    e = _req(
        request_body="a=",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert e.body_params == {"a": ""}


def test_body_params_content_type_lookup_is_case_insensitive() -> None:
    # Header name varies in capture data; lookup must be case-insensitive.
    for header_name in ("content-type", "Content-Type", "CONTENT-TYPE"):
        e = _req(
            request_body="a=1",
            headers={header_name: "application/x-www-form-urlencoded"},
        )
        assert e.body_params == {"a": "1"}, f"failed for {header_name!r}"


def test_body_params_content_type_with_charset_still_matches() -> None:
    e = _req(
        request_body="a=1",
        headers={
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        },
    )
    assert e.body_params == {"a": "1"}


# --- G. RequestEvent.all_params ---------------------------------------------


def test_all_params_merges_query_and_body() -> None:
    e = _req(
        url="https://example.com/p?a=q",
        request_body="b=body",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert e.all_params == {"a": "q", "b": "body"}


def test_all_params_body_wins_on_collision() -> None:
    e = _req(
        url="https://example.com/p?k=from_query",
        request_body="k=from_body",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert e.all_params == {"k": "from_body"}


# --- H. parse_event ---------------------------------------------------------


@pytest.mark.parametrize("missing", ["event_id", "timestamp", "type"])
def test_parse_event_raises_on_missing_required_field(missing: str) -> None:
    raw = {"event_id": 1, "timestamp": "t", "type": TYPE_LOG, "payload": {}}
    del raw[missing]
    with pytest.raises(EventParseError):
        parse_event(raw)


def test_parse_event_defaults_context_id_to_none() -> None:
    e = parse_event({
        "event_id": 1, "timestamp": "t", "type": TYPE_LOG,
        "payload": {"level": "info", "text": ""},
    })
    assert e.context_id is None


def test_parse_event_defaults_missing_payload_to_empty_dict() -> None:
    e = parse_event({"event_id": 1, "timestamp": "t", "type": TYPE_LOG})
    assert e.payload == {}


def test_parse_event_treats_none_payload_as_empty_dict() -> None:
    e = parse_event({
        "event_id": 1, "timestamp": "t", "type": TYPE_LOG, "payload": None,
    })
    assert e.payload == {}


def test_parse_event_preserves_unknown_payload_keys() -> None:
    raw = {
        "event_id": 1, "timestamp": "t", "type": TYPE_LOG,
        "payload": {"level": "info", "text": "hi", "future_key": [1, 2]},
    }
    e = parse_event(raw)
    assert e.payload["future_key"] == [1, 2]


def test_parse_event_navigation() -> None:
    e = parse_event({
        "event_id": 1, "timestamp": "t", "type": TYPE_NAVIGATION,
        "payload": {"url": "https://example.com/"},
    })
    assert isinstance(e, NavigationEvent)
    assert e.url == "https://example.com/"


def test_parse_event_navigation_defaults_url_to_empty() -> None:
    e = parse_event({
        "event_id": 1, "timestamp": "t", "type": TYPE_NAVIGATION,
        "payload": {},
    })
    assert isinstance(e, NavigationEvent)
    assert e.url == ""


def test_parse_event_request_full() -> None:
    e = parse_event({
        "event_id": 5, "timestamp": "t", "type": TYPE_REQUEST,
        "payload": {
            "method": "POST",
            "url": "https://x.example/p?a=1",
            "host": "x.example",
            "headers": {"X": "Y"},
            "request_body": "a=1",
            "initiator": "script",
            "response_status": 204,
            "response_mime": "text/plain",
            "response_headers": {"Z": "W"},
            "response_body": "ok",
        },
    })
    assert isinstance(e, RequestEvent)
    assert e.method == "POST"
    assert e.url == "https://x.example/p?a=1"
    assert e.host == "x.example"
    assert e.headers == {"X": "Y"}
    assert e.request_body == "a=1"
    assert e.initiator == "script"
    assert e.response_status == 204
    assert e.response_mime == "text/plain"
    assert e.response_headers == {"Z": "W"}
    assert e.response_body == "ok"


def test_parse_event_request_host_falls_back_to_url_hostname() -> None:
    e = parse_event({
        "event_id": 5, "timestamp": "t", "type": TYPE_REQUEST,
        "payload": {"url": "https://x.example/p"},
    })
    assert isinstance(e, RequestEvent)
    assert e.host == "x.example"


def test_parse_event_request_host_fallback_empty_when_url_unparseable() -> None:
    e = parse_event({
        "event_id": 5, "timestamp": "t", "type": TYPE_REQUEST,
        "payload": {},
    })
    assert isinstance(e, RequestEvent)
    assert e.host == ""


def test_parse_event_storage_snapshot_entries_default_to_list() -> None:
    e = parse_event({
        "event_id": 1, "timestamp": "t", "type": TYPE_STORAGE_SNAPSHOT,
        "payload": {"origin": "https://example.com", "kind": "localStorage"},
    })
    assert isinstance(e, StorageSnapshotEvent)
    assert e.entries == []


def test_parse_event_storage_snapshot_full() -> None:
    e = parse_event({
        "event_id": 1, "timestamp": "t", "type": TYPE_STORAGE_SNAPSHOT,
        "payload": {
            "origin": "https://example.com",
            "kind": "cookie",
            "entries": [{"key": "k", "value": "v"}],
        },
    })
    assert isinstance(e, StorageSnapshotEvent)
    assert e.origin == "https://example.com"
    assert e.kind == "cookie"
    assert e.entries == [{"key": "k", "value": "v"}]


def test_parse_event_script_load_defaults() -> None:
    e = parse_event({
        "event_id": 1, "timestamp": "t", "type": TYPE_SCRIPT_LOAD,
        "payload": {},
    })
    assert isinstance(e, ScriptLoadEvent)
    assert e.url == ""
    assert e.sha256 == ""


def test_parse_event_log_defaults_level_info_text_empty() -> None:
    e = parse_event({
        "event_id": 1, "timestamp": "t", "type": TYPE_LOG, "payload": {},
    })
    assert isinstance(e, LogEvent)
    assert e.level == "info"
    assert e.text == ""


@pytest.mark.parametrize(
    "ws_type",
    [TYPE_WEBSOCKET_OPEN, TYPE_WEBSOCKET_MESSAGE, TYPE_WEBSOCKET_CLOSE],
)
def test_parse_event_all_websocket_types_yield_websocket_event(ws_type: str) -> None:
    e = parse_event({
        "event_id": 1, "timestamp": "t", "type": ws_type, "payload": {},
    })
    assert isinstance(e, WebSocketEvent)
    assert e.type == ws_type


def test_parse_event_unknown_type_raises() -> None:
    with pytest.raises(EventParseError):
        parse_event({
            "event_id": 1, "timestamp": "t", "type": "not_a_real_type",
            "payload": {},
        })


# --- I. serialize_event -----------------------------------------------------


def test_serialize_event_returns_only_base_fields() -> None:
    e = LogEvent(
        event_id=3, timestamp="t", type=TYPE_LOG, context_id="ctx",
        payload={"level": "warn", "text": "msg"},
        level="warn", text="msg",
    )
    out = serialize_event(e)
    assert out == {
        "event_id": 3,
        "timestamp": "t",
        "type": TYPE_LOG,
        "context_id": "ctx",
        "payload": {"level": "warn", "text": "msg"},
    }


def test_serialize_event_does_not_emit_subclass_fields() -> None:
    e = NavigationEvent(
        event_id=1, timestamp="t", type=TYPE_NAVIGATION, context_id=None,
        payload={"url": "https://example.com/"},
        url="https://example.com/",
    )
    out = serialize_event(e)
    assert "url" not in out


def test_round_trip_log_event() -> None:
    original = LogEvent(
        event_id=1, timestamp="t", type=TYPE_LOG, context_id=None,
        payload={"level": "info", "text": "hi"},
        level="info", text="hi",
    )
    restored = parse_event(serialize_event(original))
    assert isinstance(restored, LogEvent)
    assert restored.event_id == original.event_id
    assert restored.timestamp == original.timestamp
    assert restored.level == original.level
    assert restored.text == original.text
