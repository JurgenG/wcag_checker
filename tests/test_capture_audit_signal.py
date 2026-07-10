# wcag_checker — record a real human-driven browsing session and audit
# the visited pages for WCAG 2.2 accessibility conformance.
# Copyright (C) 2026 Jurgen Gaeremyn
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Tests for the BiDi audit-hotkey signal.

The capture layer reserves the host ``wcag-checker-sentinel.invalid`` for
an in-page-JS → Python signalling channel: the injected key-down handler
fires ``fetch("https://wcag-checker-sentinel.invalid/audit?host=<host>")``
on ``Ctrl+Alt+A``, and ``network.beforeRequestSent`` routes that one
request to ``audit_requested_callback``. Hermetic: no live browser — the
signal is exercised via :meth:`BiDiCapture.dispatch_raw_event`.
"""

from __future__ import annotations

from leak_inspector.capture.bidi import SENTINEL_AUDIT_HOST, BiDiCapture


class _NoOpDriver:
    """Stand-in for the Selenium driver — never touched by the unit tests."""

    network = None
    script = None


def _before_request(*, request_id: str, url: str) -> dict:
    return {
        "context": "ctx-1",
        "timestamp": 1700000000000,
        "request": {"request": request_id, "url": url, "method": "GET", "headers": []},
        "initiator": None,
    }


def test_audit_callback_slot_defaults_none() -> None:
    capture = BiDiCapture(_NoOpDriver())
    assert capture.audit_requested_callback is None


def test_sentinel_url_fires_callback_with_host_from_query() -> None:
    capture = BiDiCapture(_NoOpDriver())
    received: list[str] = []
    capture.audit_requested_callback = received.append
    capture.dispatch_raw_event(
        "network.beforeRequestSent",
        _before_request(
            request_id="r-1",
            url=f"https://{SENTINEL_AUDIT_HOST}/audit?host=www.example.be",
        ),
    )
    assert received == ["www.example.be"]


def test_sentinel_without_host_query_passes_empty_string() -> None:
    capture = BiDiCapture(_NoOpDriver())
    received: list[str] = []
    capture.audit_requested_callback = received.append
    capture.dispatch_raw_event(
        "network.beforeRequestSent",
        _before_request(request_id="r-2", url=f"https://{SENTINEL_AUDIT_HOST}/audit"),
    )
    assert received == [""]


def test_non_sentinel_request_does_not_fire_callback() -> None:
    capture = BiDiCapture(_NoOpDriver())

    def fail(_host: str) -> None:
        raise AssertionError("callback fired for a non-sentinel URL")

    capture.audit_requested_callback = fail
    # Must not raise — an ordinary request is ignored entirely.
    capture.dispatch_raw_event(
        "network.beforeRequestSent",
        _before_request(request_id="r-3", url="https://example.be/page"),
    )


def test_callback_exception_does_not_propagate() -> None:
    capture = BiDiCapture(_NoOpDriver())

    def bad(_host: str) -> None:
        raise RuntimeError("oops")

    capture.audit_requested_callback = bad
    # A misbehaving callback must not stall the BiDi event loop.
    capture.dispatch_raw_event(
        "network.beforeRequestSent",
        _before_request(
            request_id="r-4", url=f"https://{SENTINEL_AUDIT_HOST}/audit?host=x.be"
        ),
    )


def test_no_callback_set_is_a_noop() -> None:
    capture = BiDiCapture(_NoOpDriver())
    # No callback wired — dispatching the sentinel must simply do nothing.
    capture.dispatch_raw_event(
        "network.beforeRequestSent",
        _before_request(request_id="r-5", url=f"https://{SENTINEL_AUDIT_HOST}/audit"),
    )
