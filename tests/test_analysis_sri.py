"""Tests for third-party Subresource-Integrity (SRI) gap detection.

``detect_missing_sri`` is a pure pass over the captured script index
(``page_source*.scripts.json`` rows) plus an injected third-party
predicate. It flags ``<script src>`` pulled from a third-party host with
no ``integrity`` hash — a supply-chain vector. The ``analyze_bundle``
integration test drives the same logic from a real bundle zip.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from leak_inspector.analysis.sri import (
    MissingSRI,
    ProtectedSRI,
    detect_missing_sri,
    detect_protected_sri,
)
from leak_inspector.analysis.runner import analyze_bundle
from leak_inspector.bundle import (
    BUNDLE_SCHEMA_VERSION,
    Manifest,
    TOOL_NAME,
    write_bundle,
)
from leak_inspector.events import TYPE_LOG


def _row(url: str, *, integrity=None, crossorigin=None) -> dict:
    return {"url": url, "integrity": integrity, "crossorigin": crossorigin,
            "sha256": None, "status": "200"}


# A predicate where everything outside example.com is third-party.
def _third_party(host: str) -> bool:
    return not (host == "example.com" or host.endswith(".example.com"))


# --- pure detector ----------------------------------------------------------


def test_flags_third_party_script_without_integrity() -> None:
    rows = [_row("https://cdn.tracker.net/t.js", crossorigin="anonymous")]
    got = detect_missing_sri(rows, _third_party)
    assert got == [MissingSRI(
        url="https://cdn.tracker.net/t.js", host="cdn.tracker.net",
        crossorigin="anonymous")]


def test_skips_third_party_script_with_integrity() -> None:
    rows = [_row("https://cdn.tracker.net/t.js", integrity="sha384-abc")]
    assert detect_missing_sri(rows, _third_party) == []


def test_skips_first_party_script_without_integrity() -> None:
    rows = [_row("https://example.com/app.js"),
            _row("https://static.example.com/lib.js")]
    assert detect_missing_sri(rows, _third_party) == []


def test_deduplicates_repeated_url() -> None:
    rows = [_row("https://cdn.tracker.net/t.js"),
            _row("https://cdn.tracker.net/t.js")]
    got = detect_missing_sri(rows, _third_party)
    assert [m.url for m in got] == ["https://cdn.tracker.net/t.js"]


def test_skips_entries_without_a_usable_host() -> None:
    rows = [_row(""), {"integrity": None}, _row("not-a-url")]
    assert detect_missing_sri(rows, _third_party) == []


def test_preserves_first_seen_order() -> None:
    rows = [_row("https://a.net/1.js"), _row("https://b.net/2.js"),
            _row("https://a.net/1.js")]
    got = detect_missing_sri(rows, _third_party)
    assert [m.host for m in got] == ["a.net", "b.net"]


def test_flags_third_party_stylesheet_without_integrity() -> None:
    rows = [dict(_row("https://cdn.tracker.net/site.css"), kind="stylesheet")]
    got = detect_missing_sri(rows, _third_party)
    assert got == [MissingSRI(
        url="https://cdn.tracker.net/site.css", host="cdn.tracker.net",
        kind="stylesheet")]


def test_skips_third_party_stylesheet_with_integrity() -> None:
    rows = [dict(_row("https://cdn.tracker.net/site.css",
                      integrity="sha384-abc"), kind="stylesheet")]
    assert detect_missing_sri(rows, _third_party) == []


def test_skips_first_party_stylesheet() -> None:
    rows = [dict(_row("https://example.com/site.css"), kind="stylesheet")]
    assert detect_missing_sri(rows, _third_party) == []


def test_legacy_rows_without_kind_are_scripts() -> None:
    """Rows captured before stylesheet enumeration carry no ``kind`` —
    they were all scripts."""
    rows = [_row("https://cdn.tracker.net/t.js")]
    assert detect_missing_sri(rows, _third_party)[0].kind == "script"


def test_real_vrt_row_shapes_are_flagged() -> None:
    """Seeded from the observed vrt.be capture rows (integrity all None)."""
    rows = [
        _row("https://cdn.opecloud.com/ope-var.js"),
        _row("https://gabe.hit.gemius.pl/xgemius.js"),
        _row("https://assets.adobedtm.com/extensions/EP1/AppMeasurement.min.js"),
    ]
    got = detect_missing_sri(rows, _third_party)
    assert {m.host for m in got} == {
        "cdn.opecloud.com", "gabe.hit.gemius.pl", "assets.adobedtm.com"}


# --- pure detector: protected (SRI present) ---------------------------------


def test_protected_flags_third_party_script_with_integrity() -> None:
    rows = [_row("https://cdn.jsdelivr.net/lib.js",
                 integrity="sha384-abc", crossorigin="anonymous")]
    got = detect_protected_sri(rows, _third_party)
    assert got == [ProtectedSRI(
        url="https://cdn.jsdelivr.net/lib.js", host="cdn.jsdelivr.net",
        crossorigin="anonymous")]


def test_protected_skips_third_party_script_without_integrity() -> None:
    rows = [_row("https://cdn.tracker.net/t.js")]
    assert detect_protected_sri(rows, _third_party) == []


def test_protected_skips_first_party_script_with_integrity() -> None:
    rows = [_row("https://example.com/app.js", integrity="sha384-abc")]
    assert detect_protected_sri(rows, _third_party) == []


def test_protected_flags_third_party_stylesheet_with_integrity() -> None:
    rows = [dict(_row("https://cdn.net/site.css",
                      integrity="sha384-xyz"), kind="stylesheet")]
    got = detect_protected_sri(rows, _third_party)
    assert got == [ProtectedSRI(
        url="https://cdn.net/site.css", host="cdn.net", kind="stylesheet")]


def test_protected_deduplicates_and_preserves_order() -> None:
    rows = [_row("https://a.net/1.js", integrity="sha384-a"),
            _row("https://b.net/2.js", integrity="sha384-b"),
            _row("https://a.net/1.js", integrity="sha384-a")]
    got = detect_protected_sri(rows, _third_party)
    assert [m.host for m in got] == ["a.net", "b.net"]


def test_protected_legacy_rows_without_kind_are_scripts() -> None:
    rows = [_row("https://cdn.net/t.js", integrity="sha384-a")]
    assert detect_protected_sri(rows, _third_party)[0].kind == "script"


# --- analyze_bundle integration (real bundle zip) ---------------------------


def _manifest() -> Manifest:
    return Manifest.from_dict({
        "bundle_schema": BUNDLE_SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "tool_version": "0.1.0",
        "session_id": "sess-1",
        "started_at": "2026-06-08T00:00:00Z",
        "ended_at": "2026-06-08T00:01:00Z",
        "target_url": "https://example.com/",
        "base_domain": "example.com",
        "browser": {"name": "firefox", "version": "151"},
        "profile": "default",
        "landing_url": "https://example.com/",
    })


def _bundle_with_scripts(tmp_path: Path, rows: list[dict]) -> Path:
    session = tmp_path / "session"
    session.mkdir()
    (session / "events.jsonl").write_text(
        json.dumps({"event_id": 1, "timestamp": "2026-06-08T00:00:00Z",
                    "type": TYPE_LOG,
                    "payload": {"level": "info", "text": "hi"}}) + "\n",
        encoding="utf-8")
    (session / "page_source.html").write_text("<html></html>", encoding="utf-8")
    (session / "page_source.scripts.json").write_text(
        json.dumps(rows), encoding="utf-8")
    out = tmp_path / "bundle.zip"
    write_bundle(session, _manifest(), out)
    return out


def test_analyze_bundle_populates_missing_sri(tmp_path: Path) -> None:
    out = _bundle_with_scripts(tmp_path, [
        _row("https://cdn.example/a.js", integrity="sha384-abc"),  # safe
        _row("https://tracker.example/t.js"),                      # flagged
        _row("https://example.com/app.js"),                        # first-party
    ])
    analysis = analyze_bundle(out)
    assert [m.host for m in analysis.missing_sri] == ["tracker.example"]


def test_analyze_bundle_populates_protected_sri(tmp_path: Path) -> None:
    out = _bundle_with_scripts(tmp_path, [
        _row("https://cdn.example/a.js", integrity="sha384-abc"),  # protected
        _row("https://tracker.example/t.js"),                      # missing
        _row("https://example.com/app.js", integrity="sha384-x"),  # first-party
    ])
    analysis = analyze_bundle(out)
    assert [m.host for m in analysis.protected_sri] == ["cdn.example"]


def test_analyze_bundle_no_page_source_leaves_protected_sri_empty(
        tmp_path: Path) -> None:
    session = tmp_path / "session"
    session.mkdir()
    (session / "events.jsonl").write_text("", encoding="utf-8")
    out = tmp_path / "b.zip"
    write_bundle(session, _manifest(), out)
    assert analyze_bundle(out).protected_sri == []


def test_analyze_bundle_no_page_source_leaves_missing_sri_empty(
        tmp_path: Path) -> None:
    session = tmp_path / "session"
    session.mkdir()
    (session / "events.jsonl").write_text("", encoding="utf-8")
    out = tmp_path / "b.zip"
    write_bundle(session, _manifest(), out)
    assert analyze_bundle(out).missing_sri == []


def test_analyze_bundle_aggregates_across_page_sources(tmp_path: Path) -> None:
    """An operator-triggered extra page source contributes its own scripts."""
    session = tmp_path / "session"
    session.mkdir()
    (session / "events.jsonl").write_text("", encoding="utf-8")
    (session / "page_source.html").write_text("<a/>", encoding="utf-8")
    (session / "page_source.scripts.json").write_text(
        json.dumps([_row("https://one.net/a.js")]), encoding="utf-8")
    (session / "page_source_x.example_120000.html").write_text(
        "<b/>", encoding="utf-8")
    (session / "page_source_x.example_120000.scripts.json").write_text(
        json.dumps([_row("https://two.net/b.js")]), encoding="utf-8")
    out = tmp_path / "b.zip"
    write_bundle(session, _manifest(), out)
    hosts = {m.host for m in analyze_bundle(out).missing_sri}
    assert hosts == {"one.net", "two.net"}
