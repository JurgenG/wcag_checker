"""Tests for the browser-storage overview surfaced on every report.

Capture already emits ``storage_snapshot`` events with the page's
``localStorage`` and ``sessionStorage`` keys (see
``leak_inspector/capture/storage.py``). Analysis must consume those
events, dedup to end-of-session state, and surface a structured
``StorageEntry`` list on both :class:`Analysis` and
:class:`ReportDocument`. Values are deliberately not surfaced — only
key, kind, origin, and byte size, so an auditor can see *what* is
being stored without leaking *what* it is.

The bundle's third storage kind, ``"cookie"``, is intentionally NOT
folded into this list — it's already covered by the dedicated cookie
overview built from ``Set-Cookie`` headers (which carries the
lifetime + security-flag metadata the JS-visible ``document.cookie``
loses).
"""

from __future__ import annotations

from leak_inspector.analysis import analyze_events
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.events import (
    StorageSnapshotEvent,
    TYPE_STORAGE_SNAPSHOT,
)
from leak_inspector.report.builder import build_report_document
from leak_inspector.report.document import StorageEntry


def _manifest() -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="2026-05-29T00:00:00Z",
        ended_at="2026-05-29T00:01:00Z",
        target_url="https://example.be/", base_domain="example.be",
        browser={}, profile="p", landing_url="https://example.be/",
    )


def _snap(
    *, event_id: int, origin: str, kind: str,
    entries: list[dict[str, str]],
) -> StorageSnapshotEvent:
    return StorageSnapshotEvent(
        event_id=event_id, timestamp="2026-05-29T00:00:01Z",
        type=TYPE_STORAGE_SNAPSHOT, context_id=None,
        payload={"origin": origin, "kind": kind, "entries": entries},
        origin=origin, kind=kind, entries=entries,
    )


# --- data-model basics ------------------------------------------------------


def test_storage_entry_dataclass_exists() -> None:
    """``StorageEntry`` is part of the document contract."""
    entry = StorageEntry(
        origin="https://example.be", kind="local", key="k", value_bytes=3,
    )
    assert entry.origin == "https://example.be"
    assert entry.kind == "local"
    assert entry.key == "k"
    assert entry.value_bytes == 3


def test_storage_entry_does_not_carry_value() -> None:
    """Values must NOT be exposed on the entry — only metadata."""
    entry = StorageEntry(
        origin="https://example.be", kind="local", key="k", value_bytes=3,
    )
    # Belt-and-braces: any field with the literal name ``value`` would be a
    # privacy regression. (Other attributes derived from value, like
    # ``value_bytes``, are fine.)
    assert not hasattr(entry, "value")


# --- analysis: snapshot consumption ----------------------------------------


def test_local_storage_entry_surfaces() -> None:
    events = [_snap(
        event_id=1, origin="https://example.be", kind="local",
        entries=[{"key": "user_id", "value": "abc123"}],
    )]
    analysis = analyze_events(_manifest(), events)
    assert len(analysis.storage) == 1
    e = analysis.storage[0]
    assert e.origin == "https://example.be"
    assert e.kind == "local"
    assert e.key == "user_id"
    assert e.value_bytes == len("abc123")


def test_session_storage_entry_surfaces() -> None:
    events = [_snap(
        event_id=1, origin="https://example.be", kind="session",
        entries=[{"key": "viewport", "value": "v1"}],
    )]
    analysis = analyze_events(_manifest(), events)
    assert len(analysis.storage) == 1
    assert analysis.storage[0].kind == "session"


def test_cookie_kind_excluded_from_storage_list() -> None:
    """The 'cookie' kind is rendered by the cookie section, not here."""
    events = [_snap(
        event_id=1, origin="https://example.be", kind="cookie",
        entries=[{"key": "sessionid", "value": "xyz"}],
    )]
    analysis = analyze_events(_manifest(), events)
    assert analysis.storage == []


def test_value_bytes_uses_utf8_byte_length() -> None:
    """value_bytes is the UTF-8 byte length, not the character count.

    For ASCII these are identical; for multi-byte characters they differ.
    Bytes is the more useful number ("how much is being stored").
    """
    events = [_snap(
        event_id=1, origin="https://example.be", kind="local",
        entries=[{"key": "k", "value": "café"}],  # 5 UTF-8 bytes
    )]
    analysis = analyze_events(_manifest(), events)
    assert analysis.storage[0].value_bytes == len("café".encode("utf-8"))


def test_dedup_by_origin_kind_key_last_write_wins() -> None:
    """Repeated snapshots of the same key collapse to one entry.

    The site re-snapshots periodically; we surface the *final* state.
    """
    events = [
        _snap(
            event_id=1, origin="https://example.be", kind="local",
            entries=[{"key": "k", "value": "short"}],
        ),
        _snap(
            event_id=2, origin="https://example.be", kind="local",
            entries=[{"key": "k", "value": "a-much-longer-value"}],
        ),
    ]
    analysis = analyze_events(_manifest(), events)
    assert len(analysis.storage) == 1
    assert analysis.storage[0].value_bytes == len("a-much-longer-value")


def test_local_and_session_with_same_key_are_distinct() -> None:
    """Same key in localStorage and sessionStorage = two entries."""
    events = [
        _snap(
            event_id=1, origin="https://example.be", kind="local",
            entries=[{"key": "k", "value": "L"}],
        ),
        _snap(
            event_id=2, origin="https://example.be", kind="session",
            entries=[{"key": "k", "value": "S"}],
        ),
    ]
    analysis = analyze_events(_manifest(), events)
    assert len(analysis.storage) == 2
    kinds = {e.kind for e in analysis.storage}
    assert kinds == {"local", "session"}


def test_multiple_origins_both_kept() -> None:
    events = [
        _snap(
            event_id=1, origin="https://example.be", kind="local",
            entries=[{"key": "k1", "value": "v1"}],
        ),
        _snap(
            event_id=2, origin="https://other.example.com", kind="local",
            entries=[{"key": "k2", "value": "v2"}],
        ),
    ]
    analysis = analyze_events(_manifest(), events)
    origins = {e.origin for e in analysis.storage}
    assert origins == {"https://example.be", "https://other.example.com"}


def test_stable_order_origin_kind_key() -> None:
    """Entries sorted by (origin, kind, key) — predictable for diffing."""
    events = [
        _snap(
            event_id=1, origin="https://example.be", kind="session",
            entries=[
                {"key": "z", "value": "1"},
                {"key": "a", "value": "1"},
            ],
        ),
        _snap(
            event_id=2, origin="https://example.be", kind="local",
            entries=[{"key": "m", "value": "1"}],
        ),
    ]
    analysis = analyze_events(_manifest(), events)
    order = [(e.kind, e.key) for e in analysis.storage]
    # local before session, then alphabetic by key within each kind.
    assert order == [("local", "m"), ("session", "a"), ("session", "z")]


def test_empty_entries_yields_no_storage() -> None:
    events = [_snap(
        event_id=1, origin="https://example.be", kind="local", entries=[],
    )]
    analysis = analyze_events(_manifest(), events)
    assert analysis.storage == []


def test_no_storage_snapshots_yields_empty_list() -> None:
    """A bundle with no storage_snapshot events is fine."""
    analysis = analyze_events(_manifest(), [])
    assert analysis.storage == []


# --- ReportDocument wire-up -------------------------------------------------


def test_report_document_carries_storage_list() -> None:
    events = [_snap(
        event_id=1, origin="https://example.be", kind="local",
        entries=[{"key": "k", "value": "v"}],
    )]
    analysis = analyze_events(_manifest(), events)
    document = build_report_document(analysis)
    assert len(document.storage) == 1
    assert document.storage[0].key == "k"
