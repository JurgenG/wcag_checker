# leak_inspector — record what data a website leaks during a real
# human-driven browsing session.
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

"""BiDi event capture.

Subscribes to the WebDriver BiDi event topics PROJECT.md requires and
normalizes each raw payload into the dict shape that
:func:`leak_inspector.events.parse_event` consumes.

The module is split into two clearly separated halves:

* **Normalization (pure functions and the :class:`BiDiCapture` state
  machine).** These are correct against the W3C BiDi spec and require
  no live browser to test — feed raw BiDi event dicts via
  :meth:`BiDiCapture.dispatch_raw_event` and the sink receives normalized
  events.
* **Selenium subscription wiring (:meth:`BiDiCapture.start` /
  :meth:`BiDiCapture.stop`).** Targets the Selenium ≥ 4.27 Python BiDi
  API surface (``driver.script`` for log events; ``driver.network`` for
  network events; ``driver.browsing_context`` for navigation). If your
  installed Selenium exposes BiDi under different attribute names, only
  these two methods need adapting.

Request and response bodies *are* captured via BiDi's data-collector
mechanism (``network.addDataCollector``). At session start we register
a single collector for both data types with a per-body size cap of
:data:`DEFAULT_BODY_SIZE_CAP_BYTES` (256 KB). Bodies that exceed the
cap are truncated browser-side, and binary bodies that fail UTF-8
decoding are dropped (``None``).

Request bodies are stored verbatim as decoded UTF-8 text — they are the
outbound-leak evidence the analysis is built on. Response bodies are
*not* stored raw: a response body is where the visitor's own data comes
back, so it is value-redacted before storage (see
:func:`_redact_response_body`) — JSON responses keep their field names
and value types with every scalar replaced by a placeholder, and
non-JSON responses are dropped entirely.
"""

from __future__ import annotations

import base64
import json
import threading
from contextlib import suppress
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from ..events import TYPE_LOG, TYPE_NAVIGATION, TYPE_REQUEST
from . import EventIdCounter


#: Per-body cap passed to ``network.addDataCollector`` (bytes). Bodies
#: larger than this are truncated browser-side. 256 KB covers nearly
#: all analytics POST payloads (most are <10 KB) while still recording
#: most session-replay chunks. Bump for full session-replay capture at
#: the cost of bundle size.
DEFAULT_BODY_SIZE_CAP_BYTES = 256 * 1024


#: Reserved host that the in-page key-down handler hits via ``fetch``
#: when the operator presses the screenshot shortcut. ``.invalid`` is
#: RFC-2606-reserved so this host can never resolve — but the BiDi
#: ``network.beforeRequestSent`` event still fires before the fetch is
#: even attempted, which is what gives us a clean in-band signal that
#: needs no extra subscriptions. Traffic to this host is suppressed at
#: every stage of the request-lifecycle correlator so it never appears
#: in events.jsonl.
SENTINEL_SCREENSHOT_HOST = "leak-inspector-sentinel.invalid"

#: Reserved host the in-page handler hits when the operator presses the
#: WCAG **audit** shortcut. Same ``.invalid`` sentinel trick as
#: :data:`SENTINEL_SCREENSHOT_HOST`, on a distinct host so the two signals
#: stay independent; traffic to it is suppressed identically and never
#: reaches events.jsonl. The session runner wires the callback (capture
#: does not import ``wcag``).
SENTINEL_AUDIT_HOST = "wcag-checker-sentinel.invalid"


#: Preload script that BiDi injects into every browsing context. On the
#: ``document`` capture phase (so it fires before any page handler) it
#: binds two operator shortcuts:
#:
#:   * ``Ctrl+Alt+S`` — screenshot signal → :data:`SENTINEL_SCREENSHOT_HOST`
#:   * ``Ctrl+Alt+A`` — audit signal → :data:`SENTINEL_AUDIT_HOST`
#:
#: Each fires a ``fetch`` to its sentinel host with the current page's host
#: in a ``?host=`` query. BiDi's ``network.beforeRequestSent`` catches the
#: fetch before DNS is even attempted, giving a clean in-band signal that
#: needs no extra subscriptions.
#:
#: NOTE: Avoiding ``Ctrl+Shift+*`` — those collide with Firefox's own
#: chrome shortcuts (and ``preventDefault`` in a page handler does NOT
#: block Firefox chrome shortcuts).
_PRELOAD_SCRIPT_JS = """
function() {
  document.addEventListener('keydown', function(e) {
    if (!e.ctrlKey || !e.altKey || e.shiftKey || e.metaKey) return;
    var action = null, host = null;
    if (e.key === 's' || e.key === 'S') {
      action = 'screenshot'; host = 'leak-inspector-sentinel.invalid';
    } else if (e.key === 'a' || e.key === 'A') {
      action = 'audit'; host = 'wcag-checker-sentinel.invalid';
    } else {
      return;
    }
    e.preventDefault();
    e.stopPropagation();
    try {
      fetch('https://' + host + '/' + action + '?host='
            + encodeURIComponent(location.host),
            {method: 'POST', mode: 'no-cors', keepalive: true})
        .catch(function() { /* DNS failure expected */ });
    } catch (err) { /* swallowed */ }
  }, true);
}
"""


def _sentinel_host_query(url: str) -> str:
    """Pull the ``?host=<x>`` value out of a sentinel URL (URL-decoded)."""
    parsed = urlparse(url)
    if parsed.hostname not in (SENTINEL_SCREENSHOT_HOST, SENTINEL_AUDIT_HOST):
        return ""
    qs = parse_qs(parsed.query)
    values = qs.get("host") or [""]
    return values[0]


#: Type of the per-event callback the recorder supplies.
EventSink = Callable[[dict[str, Any]], None]

#: Type of a thread-safe monotonic ``event_id`` allocator.
EventIdAllocator = Callable[[], int]


#: BiDi topic names this module subscribes to.
SUBSCRIBE_TOPICS: tuple[str, ...] = (
    "network.beforeRequestSent",
    "network.responseStarted",
    "network.responseCompleted",
    "network.fetchError",
    "browsingContext.navigationStarted",
    "browsingContext.fragmentNavigated",
    "log.entryAdded",
)


# --- pure normalization helpers --------------------------------------------


def _iso_utc(epoch_ms: int | float | None) -> str:
    """Convert a BiDi epoch-ms timestamp to ISO-8601 UTC.

    BiDi timestamps are milliseconds since the Unix epoch. If the caller
    passes ``None`` (no timestamp on the event), we substitute the current
    wall clock so the event still sorts coherently within the stream.
    """
    if epoch_ms is None:
        moment = datetime.now(timezone.utc)
    else:
        moment = datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)
    return moment.isoformat().replace("+00:00", "Z")


def _flatten_headers(bidi_headers: list[dict] | None) -> dict[str, str]:
    """Flatten BiDi's ``[{name, value: {type, value}}]`` headers into a plain dict."""
    if not bidi_headers:
        return {}
    flat: dict[str, str] = {}
    for entry in bidi_headers:
        name = entry.get("name", "")
        if not name:
            continue
        value_obj = entry.get("value")
        if isinstance(value_obj, dict):
            flat[name] = str(value_obj.get("value", ""))
        elif value_obj is not None:
            flat[name] = str(value_obj)
    return flat


def _initiator_string(bidi_initiator: dict | None) -> str | None:
    """Reduce a BiDi initiator structure to a concise descriptor.

    For script initiators, surfaces the originating script URL so reports
    can show *which* script asked for a given third-party URL.
    """
    if not bidi_initiator:
        return None
    init_type = bidi_initiator.get("type")
    if init_type == "script":
        frames = (bidi_initiator.get("stackTrace") or {}).get("callFrames") or []
        if frames and frames[0].get("url"):
            return f"script:{frames[0]['url']}"
        return "script"
    return init_type


def _host(url: str) -> str:
    return urlparse(url).hostname or ""


def _decode_bidi_body(bidi_value: dict | None) -> str | None:
    """Decode a BiDi ``BytesValue`` payload into UTF-8 text.

    BiDi returns request / response bodies as ``{"type": "string", "value":
    "..."}`` for text or ``{"type": "base64", "value": "..."}`` for binary.
    Text bodies pass through verbatim. Base64 bodies are decoded and then
    UTF-8 decoded; if either step fails (binary content that isn't valid
    UTF-8) the body is dropped (returned as ``None``) — we prefer to lose
    exotic binary data rather than embed opaque base64 blobs in the event.
    """
    if not bidi_value:
        return None
    bidi_type = bidi_value.get("type")
    value = bidi_value.get("value")
    if value is None:
        return None
    if bidi_type == "string":
        return value
    if bidi_type == "base64":
        try:
            return base64.b64decode(value).decode("utf-8")
        except (ValueError, UnicodeDecodeError, TypeError):
            return None
    return None


def _redact_json_value(value: Any) -> Any:
    """Replace every scalar leaf of a parsed JSON value with a
    type-appropriate placeholder, preserving object keys and array length.

    Strings become ``"XXXXXXX"``, numbers ``0``, booleans ``False``;
    ``null`` stays ``null``. ``bool`` is checked before ``int`` because
    in Python ``bool`` is an ``int`` subclass.
    """
    if isinstance(value, dict):
        return {key: _redact_json_value(v) for key, v in value.items()}
    if isinstance(value, list):
        return [_redact_json_value(v) for v in value]
    if value is None:
        return None
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return 0
    return "XXXXXXX"


def _redact_json_body(body: str) -> str | None:
    """Redact a JSON response body, keeping its shape but not its values.

    Returns the redacted body as a compact JSON string, or ``None`` if
    the body does not parse as JSON (e.g. truncated at the size cap) —
    fail closed, never store an un-redactable body raw.
    """
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return None
    return json.dumps(_redact_json_value(parsed))


def _redact_response_body(body: str | None, mime: str | None) -> str | None:
    """Decide what (if anything) to store for a captured response body.

    JSON responses are redacted in place (field names and value types
    kept, values stripped). Everything else — non-JSON content types, a
    missing content-type, or an absent body — is dropped, since only
    structured JSON can be redacted safely.
    """
    if body is None or not mime or "json" not in mime.lower():
        return None
    return _redact_json_body(body)


def _normalize_request(
    *,
    event_id: int,
    bidi_request_data: dict,
    bidi_response_data: dict | None,
    context: str | None,
    timestamp_ms: int | float | None,
    initiator: dict | None,
    request_body: str | None = None,
    response_body: str | None = None,
) -> dict[str, Any]:
    """Combine a BiDi request payload (with optional response) into our event dict.

    ``request_body`` and ``response_body`` come from
    :meth:`BiDiCapture._fetch_body` (which calls BiDi's ``network.getData``).
    Both are already UTF-8 text or ``None``. The request body is stored
    verbatim (it is the outbound-leak evidence); the response body is
    passed through :func:`_redact_response_body` first, so only a
    value-redacted JSON shape — never the visitor's own returned data —
    lands in the event.
    """
    request_url = bidi_request_data.get("url", "")
    response_mime = (
        bidi_response_data.get("mimeType")
        if bidi_response_data is not None
        else None
    )
    payload: dict[str, Any] = {
        "method": bidi_request_data.get("method", ""),
        "url": request_url,
        "host": _host(request_url),
        "headers": _flatten_headers(bidi_request_data.get("headers")),
        "request_body": request_body,
        "initiator": _initiator_string(initiator),
        "response_status": None,
        "response_mime": response_mime,
        "response_headers": {},
        # Response bodies carry the visitor's own returned data — store
        # only a value-redacted JSON shape, never raw (see
        # :func:`_redact_response_body`). Request bodies are untouched.
        "response_body": _redact_response_body(response_body, response_mime),
    }
    if bidi_response_data is not None:
        payload["response_status"] = bidi_response_data.get("status")
        payload["response_headers"] = _flatten_headers(bidi_response_data.get("headers"))
    return {
        "event_id": event_id,
        "timestamp": _iso_utc(timestamp_ms),
        "type": TYPE_REQUEST,
        "context_id": context,
        "payload": payload,
    }


def _normalize_navigation(*, event_id: int, bidi_event: dict) -> dict[str, Any]:
    """Convert ``browsingContext.navigationStarted`` / ``fragmentNavigated`` to a navigation event."""
    return {
        "event_id": event_id,
        "timestamp": _iso_utc(bidi_event.get("timestamp")),
        "type": TYPE_NAVIGATION,
        "context_id": bidi_event.get("context"),
        "payload": {"url": bidi_event.get("url", "")},
    }


def _normalize_log(*, event_id: int, bidi_event: dict) -> dict[str, Any]:
    """Convert ``log.entryAdded`` to a log event."""
    source = bidi_event.get("source") or {}
    return {
        "event_id": event_id,
        "timestamp": _iso_utc(bidi_event.get("timestamp")),
        "type": TYPE_LOG,
        "context_id": source.get("context"),
        "payload": {
            "level": bidi_event.get("level", "info"),
            "text": bidi_event.get("text", ""),
        },
    }


# --- capture state machine -------------------------------------------------


class BiDiCapture:
    """Forward normalized BiDi events to a sink.

    Owns three concerns:

    1. The Selenium BiDi subscription lifecycle (:meth:`start`/:meth:`stop`).
    2. Correlation of the three-event HTTP transaction
       (``beforeRequestSent`` → ``responseStarted`` → ``responseCompleted``)
       into one outbound :data:`leak_inspector.events.TYPE_REQUEST` event.
    3. Monotonic ``event_id`` assignment.

    Thread safety: BiDi callbacks may arrive on Selenium-internal threads.
    All shared state is guarded by an internal lock.
    """

    def __init__(
        self,
        driver: Any,
        event_sink: EventSink,
        *,
        next_event_id: EventIdAllocator | None = None,
        body_size_cap_bytes: int = DEFAULT_BODY_SIZE_CAP_BYTES,
    ) -> None:
        self._driver = driver
        self._sink = event_sink
        self._next_event_id_fn: EventIdAllocator = next_event_id or EventIdCounter()
        self._lock = threading.Lock()
        self._in_flight: dict[str, dict[str, Any]] = {}
        self._listener_handles: list[Any] = []
        self._body_size_cap_bytes = body_size_cap_bytes
        #: ID returned by ``network.addDataCollector`` so we can remove it on stop.
        self._data_collector_id: Any | None = None
        #: ID returned by ``script.addPreloadScript`` so we can remove it on stop.
        self._preload_script_id: Any | None = None
        #: Optional hook fired synchronously on ``navigationStarted`` *before*
        #: the navigation event itself is emitted. The recorder uses this to
        #: snapshot the outgoing page's storage. The callback receives the raw
        #: BiDi event dict; exceptions are swallowed so a misbehaving hook
        #: cannot stall BiDi event processing.
        self.pre_navigation_callback: Callable[[dict[str, Any]], None] | None = None
        #: Optional hook fired when the in-page key-down handler signals a
        #: screenshot request (via fetch to :data:`SENTINEL_SCREENSHOT_HOST`).
        #: The callback receives the page host pulled from the sentinel
        #: URL's ``?host=`` query — used by the recorder to name the
        #: resulting PNG ``screenshot_<host>_<HHMMSS>.png``. Exceptions are
        #: swallowed so a misbehaving hook cannot stall capture.
        self.screenshot_requested_callback: Callable[[str], None] | None = None
        #: Optional hook fired when the in-page key-down handler signals a
        #: WCAG audit request (via fetch to :data:`SENTINEL_AUDIT_HOST`).
        #: The callback receives the page host from the sentinel URL's
        #: ``?host=`` query; the session runner ignores it and audits
        #: ``driver.current_url`` directly. Exceptions are swallowed so a
        #: misbehaving hook cannot stall capture.
        self.audit_requested_callback: Callable[[str], None] | None = None
        #: Request-id set used to suppress sentinel traffic at every later
        #: stage (response_completed, fetch_error). Guarded by ``self._lock``.
        self._suppressed_request_ids: set[str] = set()

    # --- subscription lifecycle (Selenium-specific) ------------------------

    def start(self) -> None:
        """Subscribe to BiDi events on the driver and install callbacks.

        Targets the Selenium 4.44 Python BiDi API
        (``driver.network.add_event_handler(name, cb)`` etc.).

        Selenium's generated per-event parameter dataclasses (e.g.
        ``BeforeRequestSentParameters``) are *partial* — they declare only
        a few fields and ``_EventWrapper.from_json`` silently drops the
        rest of the W3C BiDi payload. We force raw-dict delivery on the
        events we care about so our normalizers receive the full event.

        Log/console capture is intentionally not wired in v1.0: it uses a
        different (typed) delivery shape and is not required for the DoD.
        """
        d = self._driver

        _force_raw_dict_delivery(
            d.network,
            ("before_request_sent", "response_completed", "fetch_error"),
        )
        _force_raw_dict_delivery(
            d.browsing_context,
            ("navigation_started", "fragment_navigated"),
        )

        # Register a data collector so the browser buffers request bodies
        # up to ``body_size_cap_bytes``. We retrieve them via
        # ``network.getData`` once each response completes.
        #
        # Diagnostic flip 2026-05-23: register only ``request`` (not
        # ``response``) to test whether the two collectors are
        # interacting and causing the request-body capture gap seen on
        # third-party trackers. Restore to ``["request", "response"]``
        # once the test is done.
        with suppress(Exception):
            result = d.network.add_data_collector(
                data_types=["request"],
                max_encoded_data_size=self._body_size_cap_bytes,
            )
            self._data_collector_id = (
                result.get("collector") if isinstance(result, dict) else result
            )

        def reg(domain_attr: str, event_name: str, callback: Callable) -> None:
            domain = getattr(d, domain_attr)
            callback_id = domain.add_event_handler(event_name, callback)
            self._listener_handles.append((domain_attr, event_name, callback_id))

        # Network: collapse beforeRequestSent + responseCompleted into one
        # RequestEvent (correlated by BiDi request id); fetchError emits a
        # RequestEvent with no response data.
        reg("network", "before_request_sent", self._on_before_request_sent)
        reg("network", "response_completed", self._on_response_completed)
        reg("network", "fetch_error", self._on_fetch_error)

        # BrowsingContext. ``navigation_started`` goes through a separate
        # handler so we can fire the pre-navigation snapshot hook before
        # emitting the navigation event itself. ``fragment_navigated``
        # skips the hook since in-page ``#hash`` changes do not change
        # origin.
        reg("browsing_context", "navigation_started", self._on_navigation_started)
        reg("browsing_context", "fragment_navigated", self._on_navigation)

        # Inject the operator-screenshot keydown listener into every
        # context Firefox loads. Soft-fails so an unexpected Selenium
        # variant doesn't break the rest of capture.
        with suppress(Exception):
            result = d.script.add_preload_script(
                function_declaration=_PRELOAD_SCRIPT_JS,
            )
            self._preload_script_id = (
                result.get("script") if isinstance(result, dict) else result
            )

    def stop(self) -> None:
        """Unsubscribe and emit any in-flight HTTP transactions as best-effort.

        A request that never received a response (e.g. user closed the
        browser mid-flight) is emitted with no response fields populated
        so the event is still visible in analysis.
        """
        d = self._driver
        for domain_attr, event_name, callback_id in self._listener_handles:
            domain = getattr(d, domain_attr, None)
            if domain is None:
                continue
            with suppress(Exception):
                domain.remove_event_handler(event_name, callback_id)
        self._listener_handles.clear()
        if self._data_collector_id is not None:
            with suppress(Exception):
                d.network.remove_data_collector(collector=self._data_collector_id)
            self._data_collector_id = None
        if self._preload_script_id is not None:
            with suppress(Exception):
                d.script.remove_preload_script(script=self._preload_script_id)
            self._preload_script_id = None

        with self._lock:
            stragglers = list(self._in_flight.values())
            self._in_flight.clear()
            self._suppressed_request_ids.clear()
        for entry in stragglers:
            self._emit(
                _normalize_request(
                    event_id=self._allocate_event_id(),
                    bidi_request_data=entry["request"],
                    bidi_response_data=None,
                    context=entry.get("context"),
                    timestamp_ms=entry.get("timestamp"),
                    initiator=entry.get("initiator"),
                )
            )

    # --- raw-event entrypoint (used by start() callbacks, tests, alt transports) ---

    def dispatch_raw_event(self, topic: str, bidi_event: dict) -> None:
        """Feed a raw BiDi event into the normalizer.

        Useful for unit tests and any alternate transport that does not
        go through Selenium's listener registration.
        """
        if topic == "network.beforeRequestSent":
            self._on_before_request_sent(bidi_event)
        elif topic == "network.responseCompleted":
            self._on_response_completed(bidi_event)
        elif topic == "network.fetchError":
            self._on_fetch_error(bidi_event)
        elif topic == "browsingContext.navigationStarted":
            self._on_navigation_started(bidi_event)
        elif topic == "browsingContext.fragmentNavigated":
            self._on_navigation(bidi_event)
        elif topic == "log.entryAdded":
            self._on_log_entry(bidi_event)
        # network.responseStarted is intentionally ignored: responseCompleted
        # carries the same data plus the final status/headers.

    # --- handlers ----------------------------------------------------------

    def _on_before_request_sent(self, bidi_event: dict) -> None:
        request_id = (bidi_event.get("request") or {}).get("request")
        if not request_id:
            return
        request_url = (bidi_event.get("request") or {}).get("url") or ""
        if self._is_screenshot_sentinel(request_url):
            # Suppress sentinel signal at every later stage so it never
            # leaks into events.jsonl, and route it to the callback.
            with self._lock:
                self._suppressed_request_ids.add(request_id)
            host = _sentinel_host_query(request_url)
            if self.screenshot_requested_callback is not None:
                try:
                    self.screenshot_requested_callback(host)
                except Exception:
                    pass
            return
        if self._is_audit_sentinel(request_url):
            # Same suppression + callback routing as the screenshot signal.
            with self._lock:
                self._suppressed_request_ids.add(request_id)
            host = _sentinel_host_query(request_url)
            if self.audit_requested_callback is not None:
                try:
                    self.audit_requested_callback(host)
                except Exception:
                    pass
            return
        entry = {
            "request": bidi_event.get("request") or {},
            "context": bidi_event.get("context"),
            "timestamp": bidi_event.get("timestamp"),
            "initiator": bidi_event.get("initiator"),
        }
        with self._lock:
            self._in_flight[request_id] = entry

    @staticmethod
    def _is_screenshot_sentinel(url: str) -> bool:
        if not url:
            return False
        return urlparse(url).hostname == SENTINEL_SCREENSHOT_HOST

    @staticmethod
    def _is_audit_sentinel(url: str) -> bool:
        if not url:
            return False
        return urlparse(url).hostname == SENTINEL_AUDIT_HOST

    def _on_response_completed(self, bidi_event: dict) -> None:
        request_id = (bidi_event.get("request") or {}).get("request")
        if request_id:
            with self._lock:
                if request_id in self._suppressed_request_ids:
                    return  # sentinel: never surface, even on late stages
        with self._lock:
            entry = self._in_flight.pop(request_id, None) if request_id else None
        if entry is None:
            # Late response with no matching request — emit a partial event so
            # nothing silently disappears.
            entry = {
                "request": bidi_event.get("request") or {},
                "context": bidi_event.get("context"),
                "timestamp": bidi_event.get("timestamp"),
                "initiator": bidi_event.get("initiator"),
            }
        request_body = self._fetch_body(request_id, "request") if request_id else None
        response_body = self._fetch_body(request_id, "response") if request_id else None
        self._emit(
            _normalize_request(
                event_id=self._allocate_event_id(),
                bidi_request_data=entry["request"],
                bidi_response_data=bidi_event.get("response"),
                context=entry.get("context"),
                timestamp_ms=entry.get("timestamp"),
                initiator=entry.get("initiator"),
                request_body=request_body,
                response_body=response_body,
            )
        )

    def _on_fetch_error(self, bidi_event: dict) -> None:
        request_id = (bidi_event.get("request") or {}).get("request")
        if request_id:
            with self._lock:
                if request_id in self._suppressed_request_ids:
                    return  # sentinel: never surface, even on late stages
        with self._lock:
            entry = self._in_flight.pop(request_id, None) if request_id else None
        if entry is None:
            entry = {
                "request": bidi_event.get("request") or {},
                "context": bidi_event.get("context"),
                "timestamp": bidi_event.get("timestamp"),
                "initiator": bidi_event.get("initiator"),
            }
        # Request body may still have been buffered before the failure;
        # response body will not exist.
        request_body = self._fetch_body(request_id, "request") if request_id else None
        self._emit(
            _normalize_request(
                event_id=self._allocate_event_id(),
                bidi_request_data=entry["request"],
                bidi_response_data=None,
                context=entry.get("context"),
                timestamp_ms=entry.get("timestamp"),
                initiator=entry.get("initiator"),
                request_body=request_body,
            )
        )

    def _on_navigation_started(self, bidi_event: dict) -> None:
        """Fire the pre-navigation snapshot hook (if any), then emit the event.

        The hook runs synchronously on whatever thread Selenium delivered the
        BiDi event on — typically a background thread. Exceptions in the hook
        are caught so capture stays alive even if the snapshot fails.
        """
        if self.pre_navigation_callback is not None:
            try:
                self.pre_navigation_callback(bidi_event)
            except Exception:
                pass
        self._on_navigation(bidi_event)

    def _on_navigation(self, bidi_event: dict) -> None:
        self._emit(
            _normalize_navigation(
                event_id=self._allocate_event_id(),
                bidi_event=bidi_event,
            )
        )

    def _on_log_entry(self, bidi_event: dict) -> None:
        self._emit(
            _normalize_log(
                event_id=self._allocate_event_id(),
                bidi_event=bidi_event,
            )
        )

    # --- internals ---------------------------------------------------------

    def _emit(self, event_dict: dict[str, Any]) -> None:
        self._sink(event_dict)

    def _allocate_event_id(self) -> int:
        return self._next_event_id_fn()

    def _fetch_body(self, request_id: str, data_type: str) -> str | None:
        """Retrieve a buffered request or response body via ``network.getData``.

        Best-effort: returns ``None`` if the data collector wasn't registered,
        if the body was truncated to zero, if the request wasn't tracked, or
        if BiDi rejects the call (the geckodriver implementation can return
        an error for in-progress requests, for navigations, etc.). Errors
        are swallowed so a failed fetch never stalls event emission.
        """
        if self._data_collector_id is None:
            return None
        try:
            result = self._driver.network.get_data(
                data_type=data_type,
                request=request_id,
                collector=self._data_collector_id,
            )
        except Exception:
            return None
        # The BiDi GetDataResult shape is ``{"bytes": {"type": ..., "value": ...}}``.
        # Older / variant Selenium versions may return the BytesValue directly.
        if isinstance(result, dict):
            return _decode_bidi_body(result.get("bytes") or result)
        return None


def _force_raw_dict_delivery(domain: Any, event_keys: tuple[str, ...]) -> None:
    """Patch Selenium's event wrappers to deliver raw BiDi dicts for ``event_keys``.

    Selenium's generated parameter dataclasses are partial (e.g.
    ``BeforeRequestSentParameters`` declares only ``initiator``) and the
    wrapper's ``from_json`` silently discards anything not in the dataclass.
    Setting ``_python_class = dict`` short-circuits that path and yields the
    raw BiDi event dict instead, which is what our normalizers expect.

    This reaches into Selenium internals (``domain._event_manager._event_wrappers``);
    if Selenium changes those attribute names, this is the only spot to revisit.
    """
    manager = getattr(domain, "_event_manager", None)
    wrappers = getattr(manager, "_event_wrappers", None) if manager else None
    configs = getattr(domain, "EVENT_CONFIGS", None)
    if not wrappers or not configs:
        return
    for key in event_keys:
        config = configs.get(key)
        if not config:
            continue
        wrapper = wrappers.get(config.bidi_event)
        if wrapper is not None:
            wrapper._python_class = dict


__all__ = [
    "BiDiCapture",
    "EventSink",
    "SENTINEL_SCREENSHOT_HOST",
    "SUBSCRIBE_TOPICS",
]
