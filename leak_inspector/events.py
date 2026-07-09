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

"""Normalized event dataclasses shared by capture and analysis.

A bundle's ``events.jsonl`` file contains one JSON object per line. Capture
serializes events into that form; analysis deserializes them back into the
dataclasses defined here. Tracker modules consume these dataclasses — they
never see raw dicts.

The on-the-wire schema is documented in PROJECT.md ("The bundle format").
Every event has the four base fields below; the rest lives in ``payload``
and is unpacked into typed attributes by ``parse_event``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlparse


# Event type discriminators. The strings match the ``type`` field on disk.
TYPE_NAVIGATION = "navigation"
TYPE_REQUEST = "request"
TYPE_WEBSOCKET_OPEN = "websocket_open"
TYPE_WEBSOCKET_MESSAGE = "websocket_message"
TYPE_WEBSOCKET_CLOSE = "websocket_close"
TYPE_STORAGE_SNAPSHOT = "storage_snapshot"
TYPE_SCRIPT_LOAD = "script_load"
TYPE_LOG = "log"

_WEBSOCKET_TYPES = frozenset(
    {TYPE_WEBSOCKET_OPEN, TYPE_WEBSOCKET_MESSAGE, TYPE_WEBSOCKET_CLOSE}
)


class EventParseError(ValueError):
    """Raised when a JSONL line cannot be turned into an Event."""


@dataclass
class Event:
    """Base for every bundle event.

    Attributes mirror the on-disk schema. The ``payload`` dict is retained
    verbatim so modules can read keys we have not yet promoted to typed
    attributes — a small concession to forward compatibility.
    """

    event_id: int
    timestamp: str
    type: str
    context_id: str | None
    payload: dict[str, Any]


@dataclass
class NavigationEvent(Event):
    """Top-level (or fragment) navigation in a browsing context."""

    url: str


@dataclass
class RequestEvent(Event):
    """An outbound HTTP request observed via BiDi.

    Request and response bodies are captured via BiDi's data-collector
    mechanism (``network.addDataCollector``), subject to a per-body size
    cap configured at capture time. Text bodies (form-encoded, JSON)
    arrive as decoded strings; binary bodies that cannot be UTF-8
    decoded land as ``None``.
    """

    method: str
    url: str
    host: str
    headers: dict[str, str]
    request_body: str | None
    initiator: str | None
    response_status: int | None
    response_mime: str | None
    response_headers: dict[str, str]
    response_body: str | None = None

    @property
    def query_params(self) -> dict[str, str]:
        """Parameters parsed from the URL's query string."""
        query = urlparse(self.url).query
        return dict(parse_qsl(query, keep_blank_values=True))

    @property
    def body_params(self) -> dict[str, str]:
        """Parameters parsed from a ``application/x-www-form-urlencoded`` body.

        Other body shapes (JSON, multipart) are returned as an empty dict;
        modules that care about them inspect ``request_body`` directly.
        """
        if not self.request_body:
            return {}
        content_type = ""
        for key, value in self.headers.items():
            if key.lower() == "content-type":
                content_type = value.lower()
                break
        if "application/x-www-form-urlencoded" not in content_type:
            return {}
        return dict(parse_qsl(self.request_body, keep_blank_values=True))

    @property
    def all_params(self) -> dict[str, str]:
        """Query params overlaid with body params.

        Body keys win on collision; in practice trackers rarely repeat keys
        across query and body.
        """
        merged = self.query_params
        merged.update(self.body_params)
        return merged


@dataclass
class StorageSnapshotEvent(Event):
    """A snapshot of one origin's storage at one moment.

    The full snapshot lives in ``storage/<origin>.json`` inside the bundle;
    this event references it and includes a compact view of the entries.
    """

    origin: str
    kind: str
    entries: list[dict[str, str]]


@dataclass
class ScriptLoadEvent(Event):
    """A script resource was loaded by the page.

    The script body is stored content-addressed in ``scripts/<sha256>``.
    """

    url: str
    sha256: str


@dataclass
class LogEvent(Event):
    """A ``console.*`` call, JS error, or BiDi log entry."""

    level: str
    text: str


@dataclass
class WebSocketEvent(Event):
    """A WebSocket open, message, or close.

    The discriminator is the inherited ``type`` attribute (one of the three
    ``TYPE_WEBSOCKET_*`` constants). ``url`` is set on open events; ``data``
    and ``direction`` are set on message events; close events expose ``code``
    and ``reason``. Any field that does not apply is ``None``.
    """

    url: str | None
    data: str | None
    direction: str | None
    code: int | None
    reason: str | None


def parse_event(raw: dict[str, Any]) -> Event:
    """Turn a JSONL event dict into the appropriate :class:`Event` subclass.

    Raises :class:`EventParseError` when a required base field is missing
    or when the ``type`` discriminator is unrecognized. Forward-compatible
    payload keys (ones we have not yet modeled) are preserved on
    ``Event.payload``.
    """
    try:
        event_id = raw["event_id"]
        timestamp = raw["timestamp"]
        event_type = raw["type"]
    except KeyError as exc:
        raise EventParseError(f"event missing required field: {exc.args[0]}") from exc

    context_id = raw.get("context_id")
    payload: dict[str, Any] = raw.get("payload") or {}
    base = {
        "event_id": event_id,
        "timestamp": timestamp,
        "type": event_type,
        "context_id": context_id,
        "payload": payload,
    }

    if event_type == TYPE_NAVIGATION:
        return NavigationEvent(**base, url=payload.get("url", ""))

    if event_type == TYPE_REQUEST:
        url = payload.get("url", "")
        host = payload.get("host") or (urlparse(url).hostname or "")
        return RequestEvent(
            **base,
            method=payload.get("method", ""),
            url=url,
            host=host,
            headers=payload.get("headers") or {},
            request_body=payload.get("request_body"),
            initiator=payload.get("initiator"),
            response_status=payload.get("response_status"),
            response_mime=payload.get("response_mime"),
            response_headers=payload.get("response_headers") or {},
            response_body=payload.get("response_body"),
        )

    if event_type == TYPE_STORAGE_SNAPSHOT:
        return StorageSnapshotEvent(
            **base,
            origin=payload.get("origin", ""),
            kind=payload.get("kind", ""),
            entries=list(payload.get("entries") or []),
        )

    if event_type == TYPE_SCRIPT_LOAD:
        return ScriptLoadEvent(
            **base,
            url=payload.get("url", ""),
            sha256=payload.get("sha256", ""),
        )

    if event_type == TYPE_LOG:
        return LogEvent(
            **base,
            level=payload.get("level", "info"),
            text=payload.get("text", ""),
        )

    if event_type in _WEBSOCKET_TYPES:
        return WebSocketEvent(
            **base,
            url=payload.get("url"),
            data=payload.get("data"),
            direction=payload.get("direction"),
            code=payload.get("code"),
            reason=payload.get("reason"),
        )

    raise EventParseError(f"unknown event type: {event_type!r}")


def serialize_event(event: Event) -> dict[str, Any]:
    """Serialize an :class:`Event` back into its on-disk dict form.

    The capture writer uses this to produce ``events.jsonl`` lines. The
    round-trip ``parse_event(serialize_event(e))`` must reconstruct an
    equivalent event.
    """
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "type": event.type,
        "context_id": event.context_id,
        "payload": event.payload,
    }


__all__ = [
    "Event",
    "EventParseError",
    "LogEvent",
    "NavigationEvent",
    "RequestEvent",
    "ScriptLoadEvent",
    "StorageSnapshotEvent",
    "WebSocketEvent",
    "TYPE_LOG",
    "TYPE_NAVIGATION",
    "TYPE_REQUEST",
    "TYPE_SCRIPT_LOAD",
    "TYPE_STORAGE_SNAPSHOT",
    "TYPE_WEBSOCKET_CLOSE",
    "TYPE_WEBSOCKET_MESSAGE",
    "TYPE_WEBSOCKET_OPEN",
    "parse_event",
    "serialize_event",
]