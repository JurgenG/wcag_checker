"""Tests for redaction of captured local/sessionStorage values.

The report already hides storage values (``StorageEntry`` carries only
``key`` + ``value_bytes``), but capture still writes the *raw* values
into the shareable bundle — both the ``storage_snapshot`` events and the
``storage/<host>.json`` file. Those values routinely hold the visitor's
own auth tokens / profile / email.

No consumer reads local/session value *content*: analysis uses a value
only for its byte length (the report's size signal), and consent
decoding reads values for the ``"cookie"`` kind only. So capture blanks
every local/session value to an all-``X`` string of the same UTF-8 byte
length — content gone, the one thing analysis computes preserved — while
the ``cookie`` kind and the cookie jar are left untouched.
"""

from __future__ import annotations

import json
from typing import Callable

from leak_inspector.capture.storage import (
    _redact_storage_value,
    append_snapshot_file,
    capture_snapshot,
    snapshot_to_events,
)
from leak_inspector.events import StorageSnapshotEvent, TYPE_STORAGE_SNAPSHOT


class _FakeDriver:
    """Minimal stand-in for the Selenium driver ``capture_snapshot`` uses."""

    def __init__(self, url, *, local, session, cookie="", cookies=None):
        self.current_url = url
        self._view = {"local": local, "session": session, "cookie": cookie}
        self._cookies = cookies or []

    def execute_script(self, _script):
        return self._view

    def get_cookies(self):
        return self._cookies


def _counter() -> Callable[[], int]:
    state = {"n": 0}

    def _next() -> int:
        state["n"] += 1
        return state["n"]

    return _next


# --- Phase 1: pure redaction helper -----------------------------------------


def test_redact_storage_value_blanks_to_equal_length() -> None:
    assert _redact_storage_value("token123") == "X" * 8


def test_redact_storage_value_preserves_utf8_byte_length() -> None:
    value = "café"  # 5 UTF-8 bytes (é is two bytes)
    out = _redact_storage_value(value)
    assert out == "X" * 5
    assert len(out.encode("utf-8")) == len(value.encode("utf-8"))


def test_redact_storage_value_empty() -> None:
    assert _redact_storage_value("") == ""


# --- Phase 2: capture_snapshot redacts local/session, spares cookies --------


def test_capture_snapshot_redacts_local_and_session_keeps_keys() -> None:
    driver = _FakeDriver(
        "https://site.example/",
        local={"auth_token": "secret-jwt", "theme": "dark"},
        session={"email": "a@b.com"},
    )
    snap = capture_snapshot(driver)
    assert snap["local"] == {"auth_token": "X" * len("secret-jwt"),
                             "theme": "XXXX"}
    assert snap["session"] == {"email": "X" * len("a@b.com")}


def test_capture_snapshot_leaves_cookie_kind_untouched() -> None:
    driver = _FakeDriver(
        "https://site.example/",
        local={}, session={},
        cookie="sid=raw-session-value",
        cookies=[{"name": "sid", "value": "raw-session-value",
                  "httpOnly": True}],
    )
    snap = capture_snapshot(driver)
    assert snap["cookie"] == "sid=raw-session-value"
    assert snap["cookies"] == [{"name": "sid", "value": "raw-session-value",
                                "httpOnly": True}]


# --- Phase 3: propagation to both bundle outputs ----------------------------


def test_events_from_captured_snapshot_redact_local_keep_cookie() -> None:
    driver = _FakeDriver(
        "https://s.example/",
        local={"auth": "secret"}, session={},
        cookie="c=raw", cookies=[{"name": "c", "value": "raw"}],
    )
    snap = capture_snapshot(driver)
    events = snapshot_to_events(snap, _counter())

    local_ev = next(e for e in events if e["payload"]["kind"] == "local")
    assert local_ev["payload"]["entries"] == [{"key": "auth", "value": "XXXXXX"}]

    cookie_ev = next(e for e in events if e["payload"]["kind"] == "cookie")
    assert {"key": "c", "value": "raw"} in cookie_ev["payload"]["entries"]


def test_snapshot_file_from_captured_snapshot_redacts_local(tmp_path) -> None:
    driver = _FakeDriver(
        "https://s.example/",
        local={"auth": "secret"}, session={"k": "vvvv"},
        cookie="c=raw", cookies=[{"name": "c", "value": "raw"}],
    )
    snap = capture_snapshot(driver)
    path = append_snapshot_file(tmp_path, snap)

    written = json.loads(path.read_text(encoding="utf-8"))["snapshots"][0]
    assert written["local"] == {"auth": "XXXXXX"}
    assert written["session"] == {"k": "XXXX"}
    # Cookie jar metadata is preserved verbatim.
    assert written["cookies"] == [{"name": "c", "value": "raw"}]

