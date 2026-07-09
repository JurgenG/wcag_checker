"""Tests for the BiDi-driven operator-screenshot signal.

The capture layer reserves the host ``leak-inspector-sentinel.invalid``
for an in-page-JS → recorder signalling channel: the injected key-down
handler calls ``fetch("https://leak-inspector-sentinel.invalid/screenshot
?host=<current host>")`` and the BiDi network handler routes that one
request to ``screenshot_requested_callback`` instead of emitting it as
a normal request event.
"""

from __future__ import annotations

from leak_inspector.capture.bidi import (
    SENTINEL_SCREENSHOT_HOST,
    BiDiCapture,
)


class _NoOpDriver:
    """Stand-in for the Selenium driver — never touched by the unit tests."""
    network = None
    browsing_context = None
    script = None


def _make_capture() -> tuple[BiDiCapture, list[dict]]:
    sink: list[dict] = []
    capture = BiDiCapture(_NoOpDriver(), sink.append)
    return capture, sink


def _bidi_before_request(*, request_id: str, url: str) -> dict:
    return {
        "context": "ctx-1",
        "timestamp": 1700000000000,
        "request": {
            "request": request_id,
            "url": url,
            "method": "GET",
            "headers": [],
        },
        "initiator": None,
    }


# --- callback slot ----------------------------------------------------------


def test_screenshot_requested_callback_slot_exists_and_defaults_none() -> None:
    capture, _ = _make_capture()
    assert capture.screenshot_requested_callback is None


# --- sentinel routing -------------------------------------------------------


def test_sentinel_url_fires_callback_with_host_from_query() -> None:
    """``?host=<x>`` in the sentinel URL is what the recorder uses to name the file."""
    capture, sink = _make_capture()
    received: list[str] = []
    capture.screenshot_requested_callback = lambda host: received.append(host)
    capture.dispatch_raw_event(
        "network.beforeRequestSent",
        _bidi_before_request(
            request_id="r-sent-1",
            url=f"https://{SENTINEL_SCREENSHOT_HOST}/screenshot?host=www.example.be",
        ),
    )
    assert received == ["www.example.be"]


def test_sentinel_url_does_not_emit_request_event() -> None:
    """Sentinel signalling traffic must never leak into events.jsonl."""
    capture, sink = _make_capture()
    capture.screenshot_requested_callback = lambda host: None
    capture.dispatch_raw_event(
        "network.beforeRequestSent",
        _bidi_before_request(
            request_id="r-sent-2",
            url=f"https://{SENTINEL_SCREENSHOT_HOST}/screenshot?host=x.be",
        ),
    )
    # Response completion is what would normally emit a request event;
    # sentinel must be invisible at every later stage too.
    capture.dispatch_raw_event(
        "network.responseCompleted",
        {
            "request": {"request": "r-sent-2", "url": f"https://{SENTINEL_SCREENSHOT_HOST}/screenshot"},
            "response": {"status": 200, "headers": []},
            "context": "ctx-1",
            "timestamp": 1700000000100,
        },
    )
    # Same for fetch errors (the .invalid TLD will of course fail DNS).
    capture.dispatch_raw_event(
        "network.fetchError",
        {
            "request": {"request": "r-sent-2", "url": f"https://{SENTINEL_SCREENSHOT_HOST}/screenshot"},
            "context": "ctx-1",
            "timestamp": 1700000000200,
            "errorText": "NS_ERROR_UNKNOWN_HOST",
        },
    )
    assert sink == [], f"sentinel traffic should not surface in events.jsonl, got: {sink}"


def test_callback_exception_does_not_break_capture() -> None:
    """A misbehaving callback must not stall the BiDi event loop."""
    capture, sink = _make_capture()

    def bad(host: str) -> None:
        raise RuntimeError("oops")

    capture.screenshot_requested_callback = bad
    # Must not raise; sentinel still suppressed.
    capture.dispatch_raw_event(
        "network.beforeRequestSent",
        _bidi_before_request(
            request_id="r-sent-3",
            url=f"https://{SENTINEL_SCREENSHOT_HOST}/screenshot?host=x.be",
        ),
    )
    assert sink == []


def test_non_sentinel_requests_unaffected() -> None:
    """Regression: ordinary traffic still flows through the normalizer."""
    capture, sink = _make_capture()
    capture.screenshot_requested_callback = lambda host: pytest_fail_if_called()  # noqa
    capture.dispatch_raw_event(
        "network.beforeRequestSent",
        _bidi_before_request(
            request_id="r-real-1",
            url="https://example.be/page",
        ),
    )
    capture.dispatch_raw_event(
        "network.responseCompleted",
        {
            "request": {"request": "r-real-1", "url": "https://example.be/page"},
            "response": {"status": 200, "headers": []},
            "context": "ctx-1",
            "timestamp": 1700000000100,
        },
    )
    assert len(sink) == 1
    assert sink[0]["payload"]["url"] == "https://example.be/page"


def pytest_fail_if_called() -> None:
    raise AssertionError("callback fired for a non-sentinel URL")


def test_sentinel_url_without_host_query_passes_empty_string() -> None:
    """Robust to URL shapes the injected JS could produce."""
    capture, sink = _make_capture()
    received: list[str] = []
    capture.screenshot_requested_callback = lambda host: received.append(host)
    capture.dispatch_raw_event(
        "network.beforeRequestSent",
        _bidi_before_request(
            request_id="r-sent-4",
            url=f"https://{SENTINEL_SCREENSHOT_HOST}/screenshot",
        ),
    )
    assert received == [""]
    assert sink == []
