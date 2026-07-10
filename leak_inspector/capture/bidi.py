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

"""BiDi audit-hotkey signal.

Injects a preload script into every browsing context that binds the WCAG
audit shortcut (``Ctrl+Alt+A``). The keypress fires a ``fetch()`` to a
reserved ``.invalid`` sentinel host; BiDi's ``network.beforeRequestSent``
catches that request before DNS is even attempted and routes it to a
Python callback. This in-band keypress→callback signal needs no OS-level
hooks and no extra subscriptions.

This is the only part of the fork's BiDi layer the WCAG tool uses — the
privacy tool's full network/event recorder (request/response correlation,
body capture, redaction, navigation/log events, bundle writing) was
removed in the conversion. Capture does not import ``wcag``; the session
runner wires the callback.

The subscription wiring in :meth:`BiDiCapture.start` / :meth:`stop`
targets the Selenium ≥ 4.27 Python BiDi API (``driver.network`` for the
event, ``driver.script`` for the preload script); if your Selenium
exposes BiDi under different names, those two methods are the only spot
to adapt. The signal logic itself is pure and unit-tested via
:meth:`BiDiCapture.dispatch_raw_event`, needing no live browser.
"""

from __future__ import annotations

from contextlib import suppress
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse


#: Reserved host the in-page handler hits when the operator presses the
#: WCAG audit shortcut. ``.invalid`` is RFC-2606-reserved so it can never
#: resolve — but ``network.beforeRequestSent`` still fires before the
#: fetch is attempted, which is what gives a clean in-band signal.
SENTINEL_AUDIT_HOST = "wcag-checker-sentinel.invalid"


#: Preload script BiDi injects into every browsing context. On the
#: ``document`` capture phase (so it fires before any page handler) it
#: binds ``Ctrl+Alt+A``: the keypress fires a ``fetch`` to
#: :data:`SENTINEL_AUDIT_HOST` carrying the current page host in a
#: ``?host=`` query, which ``beforeRequestSent`` catches.
#:
#: NOTE: Avoiding ``Ctrl+Shift+*`` — those collide with Firefox's own
#: chrome shortcuts (and ``preventDefault`` in a page handler does NOT
#: block Firefox chrome shortcuts).
_PRELOAD_SCRIPT_JS = """
function() {
  document.addEventListener('keydown', function(e) {
    if (!e.ctrlKey || !e.altKey || e.shiftKey || e.metaKey) return;
    // Match the physical A key via e.code, not e.key: on some layouts /
    // on macOS, Alt+A produces a different character (e.key) while
    // e.code stays 'KeyA'.
    if (e.code !== 'KeyA') return;
    e.preventDefault();
    e.stopPropagation();
    try {
      fetch('https://wcag-checker-sentinel.invalid/audit?host='
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
    if parsed.hostname != SENTINEL_AUDIT_HOST:
        return ""
    qs = parse_qs(parsed.query)
    return (qs.get("host") or [""])[0]


class BiDiCapture:
    """Inject the audit hotkey and route its sentinel signal to a callback.

    :meth:`start` registers a BiDi preload script that binds ``Ctrl+Alt+A``
    in every browsing context and subscribes to
    ``network.beforeRequestSent``. When the keypress fires its sentinel
    ``fetch``, :meth:`_on_before_request_sent` catches it and calls
    :attr:`audit_requested_callback` (set by the session runner). No page
    traffic is recorded — this is purely the hotkey signal.

    Thread safety: the BiDi callback arrives on a Selenium-internal
    thread, so :attr:`audit_requested_callback` must be safe to call from
    there (the session runner passes a thread-safe ``queue.put``). The
    object holds no other shared state, so it needs no lock of its own.
    """

    def __init__(self, driver: Any) -> None:
        self._driver = driver
        self._listener_handles: list[Any] = []
        #: ID returned by ``script.addPreloadScript`` so we can remove it on stop.
        self._preload_script_id: Any | None = None
        #: Hook fired (with the page host from the sentinel ``?host=``
        #: query) when ``Ctrl+Alt+A`` is pressed. The session runner sets
        #: it; exceptions are swallowed so a misbehaving hook cannot stall
        #: BiDi event processing.
        self.audit_requested_callback: Callable[[str], None] | None = None

    # --- subscription lifecycle (Selenium-specific) ------------------------

    def start(self) -> None:
        """Subscribe to ``before_request_sent`` and inject the preload script.

        Targets the Selenium 4.44 Python BiDi API
        (``driver.network.add_event_handler``,
        ``driver.script.add_preload_script``).

        Selenium's generated ``BeforeRequestSentParameters`` dataclass is
        *partial* — it declares only ``initiator`` and its ``from_json``
        drops the rest of the payload, including the request URL we match
        on. :func:`_force_raw_dict_delivery` forces raw-dict delivery so
        the handler receives the full event.
        """
        d = self._driver
        _force_raw_dict_delivery(d.network, ("before_request_sent",))
        callback_id = d.network.add_event_handler(
            "before_request_sent", self._on_before_request_sent
        )
        self._listener_handles.append(("network", "before_request_sent", callback_id))

        # Inject the audit-hotkey keydown listener into every context
        # Firefox loads. Soft-fails so an unexpected Selenium variant
        # doesn't break the rest of the session.
        with suppress(Exception):
            result = d.script.add_preload_script(
                function_declaration=_PRELOAD_SCRIPT_JS,
            )
            self._preload_script_id = (
                result.get("script") if isinstance(result, dict) else result
            )

    def stop(self) -> None:
        """Remove the event handler and the preload script."""
        d = self._driver
        for domain_attr, event_name, callback_id in self._listener_handles:
            domain = getattr(d, domain_attr, None)
            if domain is None:
                continue
            with suppress(Exception):
                domain.remove_event_handler(event_name, callback_id)
        self._listener_handles.clear()
        if self._preload_script_id is not None:
            with suppress(Exception):
                d.script.remove_preload_script(script=self._preload_script_id)
            self._preload_script_id = None

    # --- raw-event entrypoint (used by start()'s callback and tests) -------

    def dispatch_raw_event(self, topic: str, bidi_event: dict) -> None:
        """Feed a raw BiDi event into the handler.

        Useful for unit tests and any alternate transport that does not go
        through Selenium's listener registration. Only
        ``network.beforeRequestSent`` carries the audit signal; other
        topics are ignored.
        """
        if topic == "network.beforeRequestSent":
            self._on_before_request_sent(bidi_event)

    def _on_before_request_sent(self, bidi_event: dict) -> None:
        """Fire the audit callback iff this request is the sentinel signal."""
        request_url = (bidi_event.get("request") or {}).get("url") or ""
        if not self._is_audit_sentinel(request_url):
            return
        host = _sentinel_host_query(request_url)
        if self.audit_requested_callback is not None:
            try:
                self.audit_requested_callback(host)
            except Exception:
                pass

    @staticmethod
    def _is_audit_sentinel(url: str) -> bool:
        return bool(url) and urlparse(url).hostname == SENTINEL_AUDIT_HOST


def _force_raw_dict_delivery(domain: Any, event_keys: tuple[str, ...]) -> None:
    """Patch Selenium's event wrappers to deliver raw BiDi dicts for ``event_keys``.

    Selenium's generated parameter dataclasses are partial (e.g.
    ``BeforeRequestSentParameters`` declares only ``initiator``) and the
    wrapper's ``from_json`` silently discards anything not in the dataclass.
    Setting ``_python_class = dict`` short-circuits that path and yields the
    raw BiDi event dict instead, which is what the handler expects.

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
    "SENTINEL_AUDIT_HOST",
]
