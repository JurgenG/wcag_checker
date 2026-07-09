"""Tests for ``leak_inspector.bundle`` — manifest + writer + reader.

Covers the 41 spec rules across 13 groups: constants, ManifestError,
Manifest dataclass + to_dict + from_dict round-trip, BundleWriteError +
write_bundle, BundleReadError + BundleReader lifecycle + manifest /
events / cname_chains / storage / script accessors.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from leak_inspector.bundle import (
    BUNDLE_SCHEMA_VERSION,
    BundleReadError,
    BundleReader,
    BundleWriteError,
    Manifest,
    ManifestError,
    TOOL_NAME,
    write_bundle,
)
from leak_inspector.events import LogEvent, TYPE_LOG


# --- helpers ----------------------------------------------------------------


def _valid_manifest_dict() -> dict:
    return {
        "bundle_schema": BUNDLE_SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "tool_version": "0.1.0",
        "session_id": "sess-123",
        "started_at": "2026-05-01T00:00:00Z",
        "ended_at": "2026-05-01T00:01:00Z",
        "target_url": "https://example.com/",
        "base_domain": "example.com",
        "browser": {"name": "firefox", "version": "115"},
        "profile": "default",
        "landing_url": "https://example.com/welcome",
    }


def _valid_manifest() -> Manifest:
    return Manifest.from_dict(_valid_manifest_dict())


def _populate_session_dir(session_dir: Path) -> None:
    """Write the minimal files write_bundle requires."""
    (session_dir / "events.jsonl").write_text(
        json.dumps({
            "event_id": 1,
            "timestamp": "2026-05-01T00:00:00Z",
            "type": TYPE_LOG,
            "payload": {"level": "info", "text": "hello"},
        }) + "\n",
        encoding="utf-8",
    )


# --- A. constants + ManifestError -------------------------------------------


def test_bundle_schema_version_is_one() -> None:
    assert BUNDLE_SCHEMA_VERSION == 1


def test_tool_name_is_leak_inspector() -> None:
    assert TOOL_NAME == "leak_inspector"


def test_manifest_error_subclasses_value_error() -> None:
    assert issubclass(ManifestError, ValueError)


# --- B. Manifest dataclass shape --------------------------------------------


def test_manifest_required_positional_fields() -> None:
    m = Manifest(
        bundle_schema=1,
        tool="leak_inspector",
        tool_version="0.1.0",
        session_id="s",
        started_at="t1",
        ended_at="t2",
        target_url="https://example.com/",
        base_domain="example.com",
        browser={"name": "firefox"},
        profile="default",
    )
    assert m.bundle_schema == 1
    assert m.tool == "leak_inspector"
    assert m.tool_version == "0.1.0"
    assert m.session_id == "s"
    assert m.started_at == "t1"
    assert m.ended_at == "t2"
    assert m.target_url == "https://example.com/"
    assert m.base_domain == "example.com"
    assert m.browser == {"name": "firefox"}
    assert m.profile == "default"
    assert m.landing_url == ""  # default


def test_manifest_landing_url_is_settable() -> None:
    m = Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url="x", base_domain="x", browser={}, profile="p",
        landing_url="https://example.com/landing",
    )
    assert m.landing_url == "https://example.com/landing"


# --- C. Manifest.to_dict ----------------------------------------------------


def test_to_dict_includes_all_fields_including_empty_landing_url() -> None:
    m = Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url="x", base_domain="x", browser={"name": "firefox"}, profile="p",
    )
    d = m.to_dict()
    assert d["bundle_schema"] == 1
    assert d["tool"] == "leak_inspector"
    assert d["tool_version"] == "0.1.0"
    assert d["session_id"] == "s"
    assert d["started_at"] == "t1"
    assert d["ended_at"] == "t2"
    assert d["target_url"] == "x"
    assert d["base_domain"] == "x"
    assert d["browser"] == {"name": "firefox"}
    assert d["profile"] == "p"
    assert d["landing_url"] == ""


# --- D. Manifest.from_dict --------------------------------------------------


@pytest.mark.parametrize(
    "missing_key",
    [
        "bundle_schema", "tool", "tool_version", "session_id",
        "started_at", "ended_at", "target_url", "base_domain",
        "browser", "profile",
    ],
)
def test_from_dict_raises_when_required_field_missing(missing_key: str) -> None:
    data = _valid_manifest_dict()
    del data[missing_key]
    with pytest.raises(ManifestError):
        Manifest.from_dict(data)


def test_from_dict_raises_on_wrong_schema_version() -> None:
    data = _valid_manifest_dict()
    data["bundle_schema"] = 999
    with pytest.raises(ManifestError):
        Manifest.from_dict(data)


def test_from_dict_raises_when_browser_is_not_dict() -> None:
    data = _valid_manifest_dict()
    data["browser"] = "not a dict"
    with pytest.raises(ManifestError):
        Manifest.from_dict(data)


def test_from_dict_landing_url_defaults_to_empty_when_missing() -> None:
    data = _valid_manifest_dict()
    del data["landing_url"]
    m = Manifest.from_dict(data)
    assert m.landing_url == ""


def test_from_dict_copies_browser_dict() -> None:
    data = _valid_manifest_dict()
    m = Manifest.from_dict(data)
    data["browser"]["name"] = "MUTATED"
    assert m.browser["name"] == "firefox"


def test_manifest_round_trip() -> None:
    m1 = _valid_manifest()
    m2 = Manifest.from_dict(m1.to_dict())
    assert m1 == m2


# --- E. BundleWriteError ----------------------------------------------------


def test_bundle_write_error_subclasses_runtime_error() -> None:
    assert issubclass(BundleWriteError, RuntimeError)


# --- F. write_bundle --------------------------------------------------------


def test_write_bundle_returns_absolute_path(tmp_path: Path) -> None:
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    _populate_session_dir(session_dir)
    out_path = tmp_path / "out" / "bundle.zip"

    result = write_bundle(session_dir, _valid_manifest(), out_path)

    assert result.is_absolute()
    assert result.exists()


def test_write_bundle_raises_if_session_dir_missing(tmp_path: Path) -> None:
    with pytest.raises(BundleWriteError):
        write_bundle(
            tmp_path / "does_not_exist",
            _valid_manifest(),
            tmp_path / "out.zip",
        )


def test_write_bundle_validates_manifest_before_writing(tmp_path: Path) -> None:
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    _populate_session_dir(session_dir)

    # A manifest with a bogus schema version fails round-trip validation.
    bad = Manifest(
        bundle_schema=999, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url="x", base_domain="x", browser={}, profile="p",
    )
    out_path = tmp_path / "out.zip"
    with pytest.raises(BundleWriteError):
        write_bundle(session_dir, bad, out_path)
    assert not out_path.exists()


def test_write_bundle_raises_if_events_jsonl_missing(tmp_path: Path) -> None:
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    # No events.jsonl populated.
    with pytest.raises(BundleWriteError):
        write_bundle(session_dir, _valid_manifest(), tmp_path / "out.zip")


def test_write_bundle_writes_manifest_json_into_session_dir(tmp_path: Path) -> None:
    """manifest.json must be written and re-parseable as the same manifest."""
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    _populate_session_dir(session_dir)
    out_path = tmp_path / "out.zip"

    write_bundle(session_dir, _valid_manifest(), out_path, cleanup=False)
    manifest_json = session_dir / "manifest.json"
    assert manifest_json.is_file()
    parsed = Manifest.from_dict(json.loads(manifest_json.read_text()))
    assert parsed == _valid_manifest()


def test_write_bundle_creates_missing_parent_directories(tmp_path: Path) -> None:
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    _populate_session_dir(session_dir)
    out_path = tmp_path / "a" / "b" / "c" / "bundle.zip"

    write_bundle(session_dir, _valid_manifest(), out_path)
    assert out_path.exists()


def test_write_bundle_overwrites_existing_out_path(tmp_path: Path) -> None:
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    _populate_session_dir(session_dir)
    out_path = tmp_path / "bundle.zip"
    out_path.write_bytes(b"old garbage")

    write_bundle(session_dir, _valid_manifest(), out_path)
    # Old content must be gone; new zip must be readable.
    with zipfile.ZipFile(out_path) as zf:
        assert "manifest.json" in zf.namelist()


def test_write_bundle_zip_contains_session_files_with_relative_names(
    tmp_path: Path,
) -> None:
    session_dir = tmp_path / "session"
    (session_dir / "storage").mkdir(parents=True)
    _populate_session_dir(session_dir)
    (session_dir / "storage" / "example.com.json").write_text("{}", encoding="utf-8")

    out_path = tmp_path / "bundle.zip"
    write_bundle(session_dir, _valid_manifest(), out_path)

    with zipfile.ZipFile(out_path) as zf:
        names = zf.namelist()
    assert "manifest.json" in names
    assert "events.jsonl" in names
    assert "storage/example.com.json" in names
    # No absolute paths or leakage of session_dir name.
    for n in names:
        assert not n.startswith("/")
        assert "session" not in n.split("/")


def test_write_bundle_cleanup_removes_session_dir(tmp_path: Path) -> None:
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    _populate_session_dir(session_dir)
    write_bundle(
        session_dir, _valid_manifest(), tmp_path / "bundle.zip", cleanup=True,
    )
    assert not session_dir.exists()


def test_write_bundle_keeps_session_dir_when_cleanup_false(tmp_path: Path) -> None:
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    _populate_session_dir(session_dir)
    write_bundle(
        session_dir, _valid_manifest(), tmp_path / "bundle.zip", cleanup=False,
    )
    assert session_dir.is_dir()
    assert (session_dir / "events.jsonl").is_file()


def test_write_bundle_cleanup_is_keyword_only(tmp_path: Path) -> None:
    """``cleanup`` must not accept a positional arg (keyword-only)."""
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    _populate_session_dir(session_dir)
    with pytest.raises(TypeError):
        write_bundle(session_dir, _valid_manifest(), tmp_path / "x.zip", False)  # type: ignore[misc]


# --- G. BundleReadError -----------------------------------------------------


def test_bundle_read_error_subclasses_runtime_error() -> None:
    assert issubclass(BundleReadError, RuntimeError)


# --- H. BundleReader lifecycle ----------------------------------------------


def test_bundle_reader_accepts_str_or_path(tmp_path: Path) -> None:
    """Construction must accept Path or str and not open the zip yet."""
    p = tmp_path / "does_not_exist_yet.zip"
    r1 = BundleReader(p)
    r2 = BundleReader(str(p))
    assert r1.path == p
    assert r2.path == p


def test_bundle_reader_outside_context_raises(tmp_path: Path) -> None:
    """Accessing data without entering the context manager must raise."""
    session_dir, out_path = _make_simple_bundle(tmp_path)
    reader = BundleReader(out_path)
    with pytest.raises(BundleReadError):
        _ = reader.manifest


def test_bundle_reader_closes_zip_on_exit(tmp_path: Path) -> None:
    session_dir, out_path = _make_simple_bundle(tmp_path)
    with BundleReader(out_path) as reader:
        _ = reader.manifest
    # After exit, a non-cached operation must raise BundleReadError.
    # (``manifest`` is intentionally cached and accessible post-close.)
    with pytest.raises(BundleReadError):
        list(reader.events())


def _make_simple_bundle(tmp_path: Path) -> tuple[Path, Path]:
    """Build a valid bundle zip on disk. Returns (session_dir, zip_path)."""
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    _populate_session_dir(session_dir)
    out_path = tmp_path / "bundle.zip"
    write_bundle(session_dir, _valid_manifest(), out_path, cleanup=False)
    return session_dir, out_path


# --- I. manifest property ---------------------------------------------------


def test_reader_manifest_parses(tmp_path: Path) -> None:
    _, out_path = _make_simple_bundle(tmp_path)
    with BundleReader(out_path) as reader:
        m = reader.manifest
    assert m == _valid_manifest()


def test_reader_manifest_is_cached(tmp_path: Path) -> None:
    _, out_path = _make_simple_bundle(tmp_path)
    with BundleReader(out_path) as reader:
        first = reader.manifest
        second = reader.manifest
    assert first is second


# --- J. events() ------------------------------------------------------------


def test_reader_events_yields_parsed_events_in_order(tmp_path: Path) -> None:
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    (session_dir / "events.jsonl").write_text(
        json.dumps({"event_id": 1, "timestamp": "t", "type": TYPE_LOG,
                    "payload": {"level": "info", "text": "a"}}) + "\n" +
        json.dumps({"event_id": 2, "timestamp": "t", "type": TYPE_LOG,
                    "payload": {"level": "info", "text": "b"}}) + "\n",
        encoding="utf-8",
    )
    out_path = tmp_path / "bundle.zip"
    write_bundle(session_dir, _valid_manifest(), out_path, cleanup=False)

    with BundleReader(out_path) as reader:
        events = list(reader.events())

    assert [e.event_id for e in events] == [1, 2]
    assert all(isinstance(e, LogEvent) for e in events)


def test_reader_events_skips_empty_lines(tmp_path: Path) -> None:
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    line = json.dumps({"event_id": 1, "timestamp": "t", "type": TYPE_LOG,
                       "payload": {"level": "info", "text": "x"}})
    (session_dir / "events.jsonl").write_text(
        f"\n   \n{line}\n\n", encoding="utf-8",
    )
    out_path = tmp_path / "bundle.zip"
    write_bundle(session_dir, _valid_manifest(), out_path, cleanup=False)

    with BundleReader(out_path) as reader:
        events = list(reader.events())
    assert len(events) == 1


def test_reader_events_raises_when_events_jsonl_missing(tmp_path: Path) -> None:
    """Build a zip without events.jsonl via write_bundle's escape hatch."""
    # write_bundle requires events.jsonl, so we craft the zip manually.
    out_path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(out_path, "w") as zf:
        zf.writestr("manifest.json", json.dumps(_valid_manifest().to_dict()))

    with BundleReader(out_path) as reader:
        with pytest.raises(BundleReadError):
            list(reader.events())


# --- K. cname_chains --------------------------------------------------------


def test_reader_cname_chains_returns_empty_when_missing(tmp_path: Path) -> None:
    _, out_path = _make_simple_bundle(tmp_path)
    with BundleReader(out_path) as reader:
        assert reader.cname_chains == {}


def test_reader_cname_chains_returns_parsed_dict(tmp_path: Path) -> None:
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    _populate_session_dir(session_dir)
    (session_dir / "cname_chains.json").write_text(
        json.dumps({
            "Tracker.example": ["tracker.example", "cname.cdn.example"],
            "Other.com": ["other.com"],
        }),
        encoding="utf-8",
    )
    out_path = tmp_path / "bundle.zip"
    write_bundle(session_dir, _valid_manifest(), out_path, cleanup=False)

    with BundleReader(out_path) as reader:
        chains = reader.cname_chains

    # Hosts and chain items are lowercased.
    assert chains == {
        "tracker.example": ["tracker.example", "cname.cdn.example"],
        "other.com": ["other.com"],
    }


def test_reader_cname_chains_returns_empty_when_top_level_not_dict(
    tmp_path: Path,
) -> None:
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    _populate_session_dir(session_dir)
    (session_dir / "cname_chains.json").write_text(
        json.dumps(["not", "a", "dict"]), encoding="utf-8",
    )
    out_path = tmp_path / "bundle.zip"
    write_bundle(session_dir, _valid_manifest(), out_path, cleanup=False)

    with BundleReader(out_path) as reader:
        assert reader.cname_chains == {}


def test_reader_cname_chains_filters_defensively(tmp_path: Path) -> None:
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    _populate_session_dir(session_dir)
    # Note: JSON dict keys are always strings, so we can't test "non-string
    # key" via on-disk data; the filter remains in code as belt-and-braces
    # but is unreachable for JSON-loaded dicts.
    (session_dir / "cname_chains.json").write_text(
        json.dumps({
            "valid.example": ["a.example", 42, "b.example"],  # 42 must be dropped
            "broken": "not-a-list",  # non-list value: whole entry dropped
        }),
        encoding="utf-8",
    )
    out_path = tmp_path / "bundle.zip"
    write_bundle(session_dir, _valid_manifest(), out_path, cleanup=False)

    with BundleReader(out_path) as reader:
        chains = reader.cname_chains

    assert chains == {"valid.example": ["a.example", "b.example"]}


# --- L. storage(origin) -----------------------------------------------------


def test_reader_storage_returns_snapshot(tmp_path: Path) -> None:
    session_dir = tmp_path / "session"
    (session_dir / "storage").mkdir(parents=True)
    _populate_session_dir(session_dir)
    (session_dir / "storage" / "example.com.json").write_text(
        json.dumps({"localStorage": {"k": "v"}}), encoding="utf-8",
    )
    out_path = tmp_path / "bundle.zip"
    write_bundle(session_dir, _valid_manifest(), out_path, cleanup=False)

    with BundleReader(out_path) as reader:
        snap = reader.storage("example.com")
    assert snap == {"localStorage": {"k": "v"}}


def test_reader_storage_raises_for_unknown_origin(tmp_path: Path) -> None:
    _, out_path = _make_simple_bundle(tmp_path)
    with BundleReader(out_path) as reader:
        with pytest.raises(BundleReadError):
            reader.storage("nowhere.example")


# --- L2. storage_origins() --------------------------------------------------


def test_reader_storage_origins_lists_stems(tmp_path: Path) -> None:
    """Every ``storage/<origin>.json`` file surfaces as its stem, sorted."""
    session_dir = tmp_path / "session"
    (session_dir / "storage").mkdir(parents=True)
    _populate_session_dir(session_dir)
    for origin in ("b.example", "a.example"):
        (session_dir / "storage" / f"{origin}.json").write_text(
            json.dumps({"snapshots": []}), encoding="utf-8",
        )
    out_path = tmp_path / "bundle.zip"
    write_bundle(session_dir, _valid_manifest(), out_path, cleanup=False)

    with BundleReader(out_path) as reader:
        origins = reader.storage_origins()
    assert origins == ["a.example", "b.example"]
    # The stems round-trip back through storage(origin).
    with BundleReader(out_path) as reader:
        assert reader.storage(origins[0]) == {"snapshots": []}


def test_reader_storage_origins_empty_without_storage(tmp_path: Path) -> None:
    """A bundle with no storage directory yields an empty list, not an error."""
    _, out_path = _make_simple_bundle(tmp_path)
    with BundleReader(out_path) as reader:
        assert reader.storage_origins() == []


def test_reader_storage_origins_on_real_fixture() -> None:
    """A real captured bundle exposes its top-level origin's snapshot file."""
    from tests.fixtures.bundles import path as bundle_path

    with BundleReader(bundle_path("doccle-accept.zip")) as reader:
        origins = reader.storage_origins()
        assert origins, "fixture must carry at least one storage snapshot"
        # Each listed stem is readable and carries snapshots.
        snap = reader.storage(origins[0])
        assert "snapshots" in snap


# --- M. script(sha256) ------------------------------------------------------


def test_reader_script_returns_raw_bytes(tmp_path: Path) -> None:
    session_dir = tmp_path / "session"
    (session_dir / "scripts").mkdir(parents=True)
    _populate_session_dir(session_dir)
    body = b"\x00\x01console.log('hi');"
    (session_dir / "scripts" / "deadbeef").write_bytes(body)
    out_path = tmp_path / "bundle.zip"
    write_bundle(session_dir, _valid_manifest(), out_path, cleanup=False)

    with BundleReader(out_path) as reader:
        assert reader.script("deadbeef") == body


def test_reader_script_raises_for_unknown_hash(tmp_path: Path) -> None:
    _, out_path = _make_simple_bundle(tmp_path)
    with BundleReader(out_path) as reader:
        with pytest.raises(BundleReadError):
            reader.script("nope")


# --- N. screenshot accessor -------------------------------------------------


# A 1×1 transparent PNG — enough to exercise the bytes round-trip without
# pulling in a real image library.
_TINY_PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\x00"
    b"\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)


def test_reader_screenshot_bytes_returns_none_for_old_bundle(tmp_path: Path) -> None:
    """Backward-compat: old bundles without screenshot.png return None."""
    _, out_path = _make_simple_bundle(tmp_path)
    with BundleReader(out_path) as reader:
        assert reader.screenshot_bytes is None


def test_reader_screenshot_bytes_round_trips(tmp_path: Path) -> None:
    """A bundle with screenshot.png at the zip root exposes the bytes."""
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    _populate_session_dir(session_dir)
    (session_dir / "screenshot.png").write_bytes(_TINY_PNG_BYTES)
    out_path = tmp_path / "bundle.zip"
    write_bundle(session_dir, _valid_manifest(), out_path, cleanup=False)
    with BundleReader(out_path) as reader:
        assert reader.screenshot_bytes == _TINY_PNG_BYTES


# --- N.b. extra_screenshots iterator ----------------------------------------


def test_reader_extra_screenshots_empty_for_old_bundle(tmp_path: Path) -> None:
    """Bundles without operator-triggered screenshots yield nothing."""
    _, out_path = _make_simple_bundle(tmp_path)
    with BundleReader(out_path) as reader:
        assert list(reader.extra_screenshots()) == []


def test_reader_extra_screenshots_yields_all_timestamped_pngs(tmp_path: Path) -> None:
    """``screenshot_<host>_<HHMMSS>.png`` files are returned in sorted order."""
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    _populate_session_dir(session_dir)
    # Canonical post-load screenshot — must NOT appear in extra_screenshots.
    (session_dir / "screenshot.png").write_bytes(_TINY_PNG_BYTES)
    # Operator-triggered ones (intentionally out of order on disk so we
    # exercise the sort guarantee).
    (session_dir / "screenshot_www.example.be_143052.png").write_bytes(b"PNG-1")
    (session_dir / "screenshot_other.example.be_120000.png").write_bytes(b"PNG-2")
    (session_dir / "screenshot_www.example.be_090000.png").write_bytes(b"PNG-3")
    out_path = tmp_path / "bundle.zip"
    write_bundle(session_dir, _valid_manifest(), out_path, cleanup=False)
    with BundleReader(out_path) as reader:
        result = list(reader.extra_screenshots())
    # Canonical screenshot.png is excluded.
    names = [name for name, _ in result]
    assert "screenshot.png" not in names
    # Sorted by filename — chronological because HHMMSS is fixed-width.
    assert names == [
        "screenshot_other.example.be_120000.png",
        "screenshot_www.example.be_090000.png",
        "screenshot_www.example.be_143052.png",
    ]
    # Bytes round-trip.
    by_name = dict(result)
    assert by_name["screenshot_www.example.be_143052.png"] == b"PNG-1"
    assert by_name["screenshot_other.example.be_120000.png"] == b"PNG-2"
    assert by_name["screenshot_www.example.be_090000.png"] == b"PNG-3"


def test_reader_extra_screenshots_ignores_other_pngs(tmp_path: Path) -> None:
    """Only files matching ``screenshot_*.png`` at zip root are yielded."""
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    _populate_session_dir(session_dir)
    (session_dir / "screenshot.png").write_bytes(_TINY_PNG_BYTES)
    (session_dir / "screenshot_x.be_120000.png").write_bytes(b"ok")
    # Decoys that must not match.
    (session_dir / "random.png").write_bytes(b"nope")
    (session_dir / "snapshot_x.be_120000.png").write_bytes(b"nope")  # wrong prefix
    out_path = tmp_path / "bundle.zip"
    write_bundle(session_dir, _valid_manifest(), out_path, cleanup=False)
    with BundleReader(out_path) as reader:
        names = [name for name, _ in reader.extra_screenshots()]
    assert names == ["screenshot_x.be_120000.png"]