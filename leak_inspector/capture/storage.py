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

"""Client-side storage snapshots.

``localStorage`` / ``sessionStorage`` / ``document.cookie`` are not
visible through BiDi network events. This module captures them via
:meth:`WebDriver.execute_script` (for JS-visible state) plus
:meth:`WebDriver.get_cookies` (for ``HttpOnly`` cookies that
``document.cookie`` hides), persists the full snapshot to
``storage/<host>.json`` inside the bundle, and emits compact
``storage_snapshot`` events into the events stream — one event per
``(origin, kind)`` per the bundle schema.

``localStorage`` / ``sessionStorage`` values are **redacted at capture**
(see :func:`_redact_storage_value`): only keys and byte lengths reach
the bundle, never the raw values, which routinely hold the visitor's own
tokens / profile / PII and are never read by analysis. The ``cookie``
kind and the cookie jar are kept intact — cookies have their own
Set-Cookie analysis and consent decoding reads their values.

v1.0 scope: the top-level document's origin only. Cross-origin iframe
storage is deferred to v1.3.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from ..events import TYPE_STORAGE_SNAPSHOT


#: JS payload that returns a dict ``{local, session, cookie}`` describing
#: what JavaScript can see of the current document's storage.
SNAPSHOT_JS = """\
return {
    local:   Object.fromEntries(Object.entries(localStorage)),
    session: Object.fromEntries(Object.entries(sessionStorage)),
    cookie:  document.cookie
};
"""

_STORAGE_KINDS: tuple[str, ...] = ("local", "session", "cookie")


# --- value redaction -------------------------------------------------------


def _redact_storage_value(value: str) -> str:
    """Blank a storage value to an all-``X`` string of equal UTF-8 byte length.

    ``localStorage`` / ``sessionStorage`` routinely hold the visitor's own
    auth tokens, profile fields or email. No consumer reads the value
    *content* — analysis uses only its byte length — so capture stores a
    placeholder of the same byte length instead, keeping that size signal
    truthful while the content never reaches the (shareable) bundle.
    """
    return "X" * len(value.encode("utf-8"))


def _redact_store(store: dict) -> dict[str, str]:
    """Redact every value of a ``local`` / ``session`` store, keeping keys."""
    return {str(key): _redact_storage_value(str(value))
            for key, value in store.items()}


# --- snapshot capture ------------------------------------------------------


def capture_snapshot(driver: Any) -> dict[str, Any] | None:
    """Snapshot storage for the page currently loaded in ``driver``.

    Returns a dict with the full state for the current origin, or ``None``
    if the page has no usable origin (``about:blank``, ``chrome://`` URLs,
    etc.) or if the JS execution fails — both are normal at the very start
    and end of a session.
    """
    origin = _origin_from_url(getattr(driver, "current_url", "") or "")
    if origin is None:
        return None

    try:
        js_view = driver.execute_script(SNAPSHOT_JS) or {}
    except Exception:
        # Page may have torn down between origin check and script execution;
        # snapshots are best-effort, not load-bearing.
        return None

    cookies = _collect_cookies(driver)

    # local/session values are redacted at the source so both the
    # snapshot file and the emitted events (which derive from this dict)
    # carry placeholders, never the raw values. The cookie kind and the
    # cookie jar are left intact — cookies have their own Set-Cookie
    # analysis and consent decoding reads their values.
    return {
        "origin": origin,
        "captured_at": _now_iso(),
        "local": _redact_store(js_view.get("local") or {}),
        "session": _redact_store(js_view.get("session") or {}),
        "cookie": js_view.get("cookie") or "",
        "cookies": cookies,
    }


# --- cookie-jar collection -------------------------------------------------


def _collect_cookies(driver: Any) -> list[dict[str, Any]]:
    """Return the page's cookies, preferring the full cross-domain jar.

    ``driver.get_cookies()`` only sees cookies scoped to the top-level
    document's domain, so third-party tracker cookies (set on another
    domain while browsing the first party) are invisible to it. BiDi
    ``storage.getCookies`` enumerates the whole jar across every domain;
    when available, its result is merged with the first-party view and
    deduped by ``(domain, path, name)`` so nothing is lost if BiDi returns
    a subset. When BiDi storage is unavailable the behaviour collapses to
    the classic first-party-only capture.
    """
    cookies: list[dict[str, Any]] = []
    seen: set[tuple[Any, Any, Any]] = set()
    for source in (_full_cookie_jar(driver), _first_party_cookies(driver)):
        for cookie in source or []:
            key = (cookie.get("domain"), cookie.get("path"), cookie.get("name"))
            if key in seen:
                continue
            seen.add(key)
            cookies.append(cookie)
    return cookies


def _first_party_cookies(driver: Any) -> list[dict[str, Any]]:
    """Classic ``WebDriver.get_cookies()`` — top-level origin cookies only."""
    try:
        return list(driver.get_cookies() or [])
    except Exception:
        return []


def _full_cookie_jar(driver: Any) -> list[dict[str, Any]] | None:
    """Return every cookie in the browser's jar via BiDi ``storage.getCookies``.

    An unfiltered ``storage.getCookies`` enumerates cookies for *all*
    domains — including the third-party tracker cookies that are the whole
    point of exposure-mode capture. Returns ``None`` when BiDi storage is
    unavailable or the call fails, so :func:`_collect_cookies` falls back to
    the first-party-only view.
    """
    try:
        result = driver.storage.get_cookies()
    except Exception:
        return None
    cookies = getattr(result, "cookies", None)
    if cookies is None:
        return None
    return [_storage_cookie_to_dict(cookie) for cookie in cookies]


def _storage_cookie_to_dict(cookie: Any) -> dict[str, Any]:
    """Map a BiDi ``StorageCookie`` onto the ``get_cookies()`` dict shape.

    Keeps the snapshot's ``cookies`` entries uniform regardless of source.
    A cookie value may arrive wrapped in a BiDi ``BytesValue``; unwrap it to
    the plain string it carries.
    """
    value = getattr(cookie, "value", None)
    if hasattr(value, "value"):  # BytesValue wrapper
        value = value.value
    return {
        "name": getattr(cookie, "name", None),
        "value": value,
        "domain": getattr(cookie, "domain", None),
        "path": getattr(cookie, "path", None),
        "httpOnly": getattr(cookie, "http_only", None),
        "secure": getattr(cookie, "secure", None),
        "sameSite": getattr(cookie, "same_site", None),
        "expiry": getattr(cookie, "expiry", None),
    }


# --- bundle layout I/O -----------------------------------------------------


def append_snapshot_file(session_dir: Path, snapshot: dict[str, Any]) -> Path:
    """Append ``snapshot`` to ``storage/<host>.json`` inside ``session_dir``.

    File format::

        {"origin": "<full-origin>", "snapshots": [snapshot, snapshot, ...]}

    Returns the path written to. Creates the file (and parent directory)
    on first call for an origin.
    """
    host = _host_filename(snapshot["origin"])
    path = session_dir / "storage" / f"{host}.json"
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        if "snapshots" not in data:
            data = {"origin": snapshot["origin"], "snapshots": []}
    else:
        data = {"origin": snapshot["origin"], "snapshots": []}

    data["snapshots"].append(snapshot)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return path


# --- event emission --------------------------------------------------------


def snapshot_to_events(
    snapshot: dict[str, Any],
    next_event_id: Callable[[], int],
) -> list[dict[str, Any]]:
    """Build the three ``storage_snapshot`` event dicts for one snapshot.

    The bundle schema models one event per ``(origin, kind)``; ``kind`` is
    ``"local"``, ``"session"``, or ``"cookie"``. ``entries`` carries a
    compact ``[{key, value}, ...]`` view; the full snapshot (with cookie
    metadata like ``httpOnly`` and ``expiry``) is in ``storage/<host>.json``.
    """
    origin = snapshot["origin"]
    captured_at = snapshot["captured_at"]
    events: list[dict[str, Any]] = []
    for kind in _STORAGE_KINDS:
        entries = _entries_for_kind(snapshot, kind)
        events.append({
            "event_id": next_event_id(),
            "timestamp": captured_at,
            "type": TYPE_STORAGE_SNAPSHOT,
            "context_id": None,
            "payload": {
                "origin": origin,
                "kind": kind,
                "entries": entries,
            },
        })
    return events


# --- recorder-facing convenience ------------------------------------------


def take_snapshot(
    driver: Any,
    session_dir: Path,
    *,
    next_event_id: Callable[[], int],
    event_sink: Callable[[dict[str, Any]], None],
) -> dict[str, Any] | None:
    """Capture, persist, and emit a single storage snapshot.

    Returns the snapshot dict (for the recorder's logging convenience),
    or ``None`` if there was nothing to snapshot.
    """
    snapshot = capture_snapshot(driver)
    if snapshot is None:
        return None
    append_snapshot_file(session_dir, snapshot)
    for event in snapshot_to_events(snapshot, next_event_id):
        event_sink(event)
    return snapshot


# --- helpers ---------------------------------------------------------------


def _origin_from_url(url: str) -> str | None:
    """Reduce ``url`` to a ``scheme://host[:port]`` origin, or ``None`` for non-web schemes."""
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _host_filename(origin: str) -> str:
    """Derive a filesystem-safe filename stem from an origin string.

    Matches the convention :class:`leak_inspector.bundle.BundleReader.storage`
    uses on the read side (looked up by hostname).
    """
    parsed = urlparse(origin)
    host = parsed.hostname or "unknown"
    if parsed.port:
        host = f"{host}_{parsed.port}"
    return host


def _entries_for_kind(snapshot: dict[str, Any], kind: str) -> list[dict[str, str]]:
    """Project a snapshot into the compact ``[{key, value}]`` per-event view."""
    if kind in ("local", "session"):
        store = snapshot.get(kind) or {}
        return [{"key": str(k), "value": str(v)} for k, v in store.items()]
    if kind == "cookie":
        return _cookie_entries(snapshot)
    return []


def _cookie_entries(snapshot: dict[str, Any]) -> list[dict[str, str]]:
    """Merge ``driver.get_cookies()`` and ``document.cookie`` into one list.

    Prefers the structured ``get_cookies()`` view (it includes ``HttpOnly``
    cookies that ``document.cookie`` cannot see). Falls back to parsing the
    raw cookie string for anything ``get_cookies()`` missed.
    """
    entries: list[dict[str, str]] = []
    seen: set[str] = set()
    for cookie in snapshot.get("cookies", []) or []:
        name = cookie.get("name")
        if not name or name in seen:
            continue
        entries.append({"key": str(name), "value": str(cookie.get("value", ""))})
        seen.add(name)
    raw = snapshot.get("cookie") or ""
    if raw:
        for part in raw.split(";"):
            part = part.strip()
            if "=" not in part:
                continue
            key, _, value = part.partition("=")
            key = key.strip()
            if key and key not in seen:
                entries.append({"key": key, "value": value.strip()})
                seen.add(key)
    return entries


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string ending in ``Z``."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


__all__ = [
    "SNAPSHOT_JS",
    "append_snapshot_file",
    "capture_snapshot",
    "snapshot_to_events",
    "take_snapshot",
]
