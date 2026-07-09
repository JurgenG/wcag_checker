"""Tests for the bundle reader's size caps (anti-zip-bomb).

A hostile bundle is just a zip — a zip can compress 1 GB of zeros to
1 MB on disk. Without a cap, ``raw.read()`` on the inflated entry
OOMs the analyst on bundle open. Worse, a single 10 GB JSONL line
inside ``events.jsonl`` does the same thing line by line.

The fix is two-layered:

1. **File-size caps** via ``zf.getinfo(name).file_size`` (uncompressed)
   on every entry the reader inflates whole-file (``manifest.json``,
   ``cname_chains.json``, ``storage/<origin>.json``, scripts,
   screenshots). Exceeding the cap raises ``BundleReadError``.

2. **Per-line cap** on ``events.jsonl`` via bounded ``readline()`` —
   oversized lines are dropped and counted on the reader, so the rest
   of the stream still processes cleanly.

The caps are intentionally generous (50× the largest real-world bundle
observed in our fixtures) so legitimate captures never trip them.
Hostile compression-ratio attacks fail at the first inflated entry.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from leak_inspector.bundle.reader import BundleReader, BundleReadError


def _valid_manifest_bytes() -> bytes:
    return json.dumps({
        "bundle_schema": 1,
        "tool": "leak_inspector",
        "tool_version": "0.1.0",
        "session_id": "s",
        "started_at": "2026-06-04T00:00:00Z",
        "ended_at": "2026-06-04T00:01:00Z",
        "target_url": "https://example.com/",
        "base_domain": "example.com",
        "browser": {},
        "profile": "p",
        "landing_url": "https://example.com/",
    }).encode("utf-8")


def _make_zip(tmp_path: Path, name: str, members: dict[str, bytes]) -> Path:
    """Build a zip on disk with the named members. Returns the path."""
    path = tmp_path / name
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry, data in members.items():
            zf.writestr(entry, data)
    return path


# --- file-size caps -------------------------------------------------------


def test_oversized_manifest_raises(tmp_path: Path, monkeypatch) -> None:
    """A manifest larger than the cap is refused before being read into memory."""
    from leak_inspector.bundle import reader as reader_module

    monkeypatch.setattr(reader_module, "_MAX_MANIFEST_BYTES", 1024)  # 1 KB cap
    huge_manifest = json.dumps({"junk": "x" * 4096}).encode("utf-8")
    path = _make_zip(tmp_path, "bomb.zip", {"manifest.json": huge_manifest})

    with BundleReader(path) as bundle, pytest.raises(BundleReadError) as exc_info:
        _ = bundle.manifest
    assert "manifest" in str(exc_info.value).lower()
    assert "size" in str(exc_info.value).lower() or "cap" in str(exc_info.value).lower()


def test_oversized_cname_chains_raises(tmp_path: Path, monkeypatch) -> None:
    from leak_inspector.bundle import reader as reader_module
    monkeypatch.setattr(reader_module, "_MAX_CNAME_BYTES", 1024)
    huge = json.dumps({f"host-{i}.example.com": ["a"] for i in range(10000)}).encode("utf-8")
    path = _make_zip(tmp_path, "bomb.zip", {
        "manifest.json": _valid_manifest_bytes(),
        "cname_chains.json": huge,
    })
    with BundleReader(path) as bundle, pytest.raises(BundleReadError):
        _ = bundle.cname_chains


def test_oversized_storage_raises(tmp_path: Path, monkeypatch) -> None:
    from leak_inspector.bundle import reader as reader_module
    monkeypatch.setattr(reader_module, "_MAX_STORAGE_BYTES", 1024)
    huge = json.dumps({"localStorage": {"key": "x" * 4096}}).encode("utf-8")
    path = _make_zip(tmp_path, "bomb.zip", {
        "manifest.json": _valid_manifest_bytes(),
        "storage/example.com.json": huge,
    })
    with BundleReader(path) as bundle, pytest.raises(BundleReadError):
        _ = bundle.storage("example.com")


def test_oversized_script_raises(tmp_path: Path, monkeypatch) -> None:
    from leak_inspector.bundle import reader as reader_module
    monkeypatch.setattr(reader_module, "_MAX_SCRIPT_BYTES", 1024)
    path = _make_zip(tmp_path, "bomb.zip", {
        "manifest.json": _valid_manifest_bytes(),
        "scripts/abc123": b"x" * 4096,
    })
    with BundleReader(path) as bundle, pytest.raises(BundleReadError):
        _ = bundle.script("abc123")


def test_oversized_screenshot_raises(tmp_path: Path, monkeypatch) -> None:
    from leak_inspector.bundle import reader as reader_module
    monkeypatch.setattr(reader_module, "_MAX_SCREENSHOT_BYTES", 1024)
    path = _make_zip(tmp_path, "bomb.zip", {
        "manifest.json": _valid_manifest_bytes(),
        "screenshot.png": b"x" * 4096,
    })
    with BundleReader(path) as bundle, pytest.raises(BundleReadError):
        _ = bundle.screenshot_bytes


# --- under-cap reads still work -------------------------------------------


def test_within_cap_manifest_reads_normally(tmp_path: Path) -> None:
    """A normal-size manifest under the cap reads as before."""
    path = _make_zip(tmp_path, "normal.zip", {
        "manifest.json": _valid_manifest_bytes(),
    })
    with BundleReader(path) as bundle:
        m = bundle.manifest
    assert m.base_domain == "example.com"


def test_within_cap_cname_chains_reads_normally(tmp_path: Path) -> None:
    chains = {"a.example.com": ["a.example.com", "b.example.com"]}
    path = _make_zip(tmp_path, "normal.zip", {
        "manifest.json": _valid_manifest_bytes(),
        "cname_chains.json": json.dumps(chains).encode("utf-8"),
    })
    with BundleReader(path) as bundle:
        assert bundle.cname_chains == {
            "a.example.com": ["a.example.com", "b.example.com"]
        }


# --- per-line cap on events.jsonl -----------------------------------------


def _event_line(event_id: int, host: str = "example.com") -> bytes:
    return (json.dumps({
        "event_id": event_id,
        "timestamp": "2026-06-04T00:00:00Z",
        "type": "request",
        "context_id": None,
        "payload": {
            "method": "GET",
            "url": f"https://{host}/path",
            "host": host,
            "headers": {},
        },
    }) + "\n").encode("utf-8")


def test_oversized_event_line_is_dropped(tmp_path: Path, monkeypatch) -> None:
    """A bomb event line is skipped; the surrounding events still yield."""
    from leak_inspector.bundle import reader as reader_module
    monkeypatch.setattr(reader_module, "_MAX_EVENT_LINE_BYTES", 1024)  # 1 KB

    # An event with a 4 KB-padded URL — exceeds the cap by 4×.
    bomb = (json.dumps({
        "event_id": 2,
        "timestamp": "t",
        "type": "request",
        "context_id": None,
        "payload": {
            "method": "GET",
            "url": "https://example.com/" + ("x" * 4096),
            "host": "example.com",
            "headers": {},
        },
    }) + "\n").encode("utf-8")
    contents = _event_line(1) + bomb + _event_line(3)

    path = _make_zip(tmp_path, "bomb.zip", {
        "manifest.json": _valid_manifest_bytes(),
        "events.jsonl": contents,
    })
    with BundleReader(path) as bundle:
        events = list(bundle.events())
        assert bundle.truncated_events == 1
    # The pre- and post-bomb events come through cleanly.
    assert [e.event_id for e in events] == [1, 3]


def test_truncated_events_counter_starts_at_zero(tmp_path: Path) -> None:
    path = _make_zip(tmp_path, "normal.zip", {
        "manifest.json": _valid_manifest_bytes(),
        "events.jsonl": _event_line(1) + _event_line(2),
    })
    with BundleReader(path) as bundle:
        assert bundle.truncated_events == 0
        list(bundle.events())
        assert bundle.truncated_events == 0


def test_total_events_file_size_cap(tmp_path: Path, monkeypatch) -> None:
    """A pathologically large events.jsonl is rejected before iteration starts."""
    from leak_inspector.bundle import reader as reader_module
    monkeypatch.setattr(reader_module, "_MAX_EVENTS_FILE_BYTES", 1024)

    # Many small lines that together exceed the file-size cap.
    contents = b"".join(_event_line(i) for i in range(1000))
    assert len(contents) > 1024  # sanity
    path = _make_zip(tmp_path, "bomb.zip", {
        "manifest.json": _valid_manifest_bytes(),
        "events.jsonl": contents,
    })
    with BundleReader(path) as bundle, pytest.raises(BundleReadError):
        list(bundle.events())


# --- multi-line drain: oversized line doesn't desync the stream ----------


def test_oversized_line_does_not_desync_subsequent_lines(
    tmp_path: Path, monkeypatch,
) -> None:
    """After dropping a bomb line, the stream must resynchronize on \\n.

    Bug shape: if the per-line cap is implemented naively with
    ``readline(N)``, an N+1-byte line gets read as two halves and the
    second half becomes a malformed start of the *next* parse.
    """
    from leak_inspector.bundle import reader as reader_module
    monkeypatch.setattr(reader_module, "_MAX_EVENT_LINE_BYTES", 512)

    # Build a bomb line that's 4× the cap, then 3 normal lines after.
    bomb_payload = "x" * 2048
    bomb = (json.dumps({
        "event_id": 99, "timestamp": "t", "type": "request",
        "context_id": None,
        "payload": {
            "method": "GET",
            "url": f"https://example.com/{bomb_payload}",
            "host": "example.com", "headers": {},
        },
    }) + "\n").encode("utf-8")
    assert len(bomb) > 512
    contents = bomb + _event_line(1) + _event_line(2) + _event_line(3)

    path = _make_zip(tmp_path, "bomb.zip", {
        "manifest.json": _valid_manifest_bytes(),
        "events.jsonl": contents,
    })
    with BundleReader(path) as bundle:
        events = list(bundle.events())
        assert bundle.truncated_events == 1
    # Resync worked: 1, 2, 3 all parse cleanly.
    assert [e.event_id for e in events] == [1, 2, 3]
