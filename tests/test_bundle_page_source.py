"""Round-trip tests for page-source + script-body bundle artifacts.

Capture writes, per screenshot, a verbatim ``page_source{suffix}.html``,
a ``page_source{suffix}.scripts.json`` index, and content-addressed
``scripts/<sha256>`` bodies. These assert the writer carries all three
into the zip and the reader exposes them with size caps enforced.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from leak_inspector.bundle import (
    BUNDLE_SCHEMA_VERSION,
    BundleReadError,
    BundleReader,
    Manifest,
    TOOL_NAME,
    write_bundle,
)
from leak_inspector.bundle.reader import _MAX_PAGE_SOURCE_BYTES
from leak_inspector.events import TYPE_LOG


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


def _session_dir(tmp_path: Path) -> Path:
    session = tmp_path / "session"
    session.mkdir()
    (session / "events.jsonl").write_text(
        json.dumps({
            "event_id": 1,
            "timestamp": "2026-06-08T00:00:00Z",
            "type": TYPE_LOG,
            "payload": {"level": "info", "text": "hi"},
        }) + "\n",
        encoding="utf-8",
    )
    return session


def _bundle_with_page_source(tmp_path: Path, *, html: str = "<html><head>"
                             "<script src='https://cdn.example/a.js' "
                             "integrity='sha384-abc'></script></head></html>",
                             body: bytes = b"console.log(1)") -> Path:
    session = _session_dir(tmp_path)
    sha = hashlib.sha256(body).hexdigest()
    (session / "page_source.html").write_text(html, encoding="utf-8")
    (session / "page_source.scripts.json").write_text(json.dumps([
        {"url": "https://cdn.example/a.js", "integrity": "sha384-abc",
         "crossorigin": "anonymous", "sha256": sha, "status": "200"},
        {"url": "https://tracker.example/t.js", "integrity": None,
         "crossorigin": None, "sha256": None, "status": "cors-error"},
    ]), encoding="utf-8")
    scripts = session / "scripts"
    scripts.mkdir()
    (scripts / sha).write_bytes(body)
    out = tmp_path / "bundle.zip"
    write_bundle(session, _manifest(), out)
    return out


# --- writer carries the files ----------------------------------------------


def test_page_source_files_land_in_zip(tmp_path: Path) -> None:
    out = _bundle_with_page_source(tmp_path)
    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
    assert "page_source.html" in names
    assert "page_source.scripts.json" in names
    assert any(n.startswith("scripts/") for n in names)


# --- reader: page_source ----------------------------------------------------


def test_page_source_reads_verbatim(tmp_path: Path) -> None:
    out = _bundle_with_page_source(tmp_path, html="<html>verbatim &amp;</html>")
    with BundleReader(out) as r:
        assert r.page_source() == "<html>verbatim &amp;</html>"


def test_page_source_absent_returns_none(tmp_path: Path) -> None:
    session = _session_dir(tmp_path)
    out = tmp_path / "b.zip"
    write_bundle(session, _manifest(), out)
    with BundleReader(out) as r:
        assert r.page_source() is None


def test_page_sources_iterates_all_sorted(tmp_path: Path) -> None:
    session = _session_dir(tmp_path)
    (session / "page_source.html").write_text("<root/>", encoding="utf-8")
    (session / "page_source_cdn.example_120000.html").write_text(
        "<extra/>", encoding="utf-8")
    out = tmp_path / "b.zip"
    write_bundle(session, _manifest(), out)
    with BundleReader(out) as r:
        got = list(r.page_sources())
    assert got == [
        ("page_source.html", "<root/>"),
        ("page_source_cdn.example_120000.html", "<extra/>"),
    ]


def test_page_source_over_cap_raises(tmp_path: Path) -> None:
    session = _session_dir(tmp_path)
    (session / "page_source.html").write_text(
        "x" * (_MAX_PAGE_SOURCE_BYTES + 1), encoding="utf-8")
    out = tmp_path / "b.zip"
    write_bundle(session, _manifest(), out)
    with BundleReader(out) as r:
        with pytest.raises(BundleReadError):
            r.page_source()


# --- reader: scripts index + bodies ----------------------------------------


def test_page_source_scripts_index_round_trips(tmp_path: Path) -> None:
    out = _bundle_with_page_source(tmp_path)
    with BundleReader(out) as r:
        index = r.page_source_scripts()
    assert len(index) == 2
    assert index[0]["integrity"] == "sha384-abc"
    assert index[0]["crossorigin"] == "anonymous"
    assert index[1]["sha256"] is None
    assert index[1]["status"] == "cors-error"


def test_indexed_script_body_resolves_via_sha(tmp_path: Path) -> None:
    body = b"alert('x')"
    out = _bundle_with_page_source(tmp_path, body=body)
    with BundleReader(out) as r:
        sha = r.page_source_scripts()[0]["sha256"]
        assert r.script(sha) == body


def test_page_source_scripts_absent_returns_none(tmp_path: Path) -> None:
    session = _session_dir(tmp_path)
    out = tmp_path / "b.zip"
    write_bundle(session, _manifest(), out)
    with BundleReader(out) as r:
        assert r.page_source_scripts() is None


def test_page_source_script_indexes_iterates_all_sorted(tmp_path: Path) -> None:
    session = _session_dir(tmp_path)
    (session / "page_source.scripts.json").write_text(
        json.dumps([{"url": "https://a.net/a.js"}]), encoding="utf-8")
    (session / "page_source_cdn.example_120000.scripts.json").write_text(
        json.dumps([{"url": "https://b.net/b.js"}]), encoding="utf-8")
    out = tmp_path / "b.zip"
    write_bundle(session, _manifest(), out)
    with BundleReader(out) as r:
        got = list(r.page_source_script_indexes())
    assert got == [
        ("page_source.scripts.json", [{"url": "https://a.net/a.js"}]),
        ("page_source_cdn.example_120000.scripts.json",
         [{"url": "https://b.net/b.js"}]),
    ]


def test_page_source_script_indexes_empty_when_absent(tmp_path: Path) -> None:
    session = _session_dir(tmp_path)
    out = tmp_path / "b.zip"
    write_bundle(session, _manifest(), out)
    with BundleReader(out) as r:
        assert list(r.page_source_script_indexes()) == []