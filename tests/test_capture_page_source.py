"""Tests for ``leak_inspector.capture.page_source``.

The helper runs alongside each screenshot: it writes a verbatim
``page_source{suffix}.html``, enumerates ``<script src>`` from the live
DOM (read-only, no network), server-side fetches each body into
``scripts/<sha256>``, and writes a ``page_source{suffix}.scripts.json``
index. All driver/network access is soft-fail. A fake driver and an
injected fetcher keep these offline.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from leak_inspector.capture import page_source
from leak_inspector.capture.page_source import (
    _fetch_script_body,
    capture_page_source,
)


class _FakeDriver:
    """Minimal stand-in exposing the two members the helper touches."""

    def __init__(self, *, page_source: str = "<html></html>",
                 scripts: list | None = None,
                 raise_source: bool = False,
                 raise_enum: bool = False) -> None:
        self._page_source = page_source
        self._scripts = scripts if scripts is not None else []
        self._raise_source = raise_source
        self._raise_enum = raise_enum

    @property
    def page_source(self) -> str:
        if self._raise_source:
            raise RuntimeError("session dead")
        return self._page_source

    def execute_script(self, _script: str):
        if self._raise_enum:
            raise RuntimeError("no DOM")
        return self._scripts


def _ok_fetch(bodies: dict[str, bytes]):
    """Build a fetcher returning ``(bytes, status)`` from a url→body map."""
    def fetch(url: str):
        if url in bodies:
            return bodies[url], "200"
        return None, "cors-error"
    return fetch


def _index(session: Path, suffix: str = "") -> list[dict]:
    return json.loads(
        (session / f"page_source{suffix}.scripts.json").read_text("utf-8"))


# --- page source ------------------------------------------------------------


def test_writes_page_source_verbatim(tmp_path: Path) -> None:
    driver = _FakeDriver(page_source="<html>raw &amp; u/></html>")
    capture_page_source(driver, tmp_path, suffix="", fetch=_ok_fetch({}))
    assert (tmp_path / "page_source.html").read_text("utf-8") == \
        "<html>raw &amp; u/></html>"


def test_suffix_mirrors_screenshot_naming(tmp_path: Path) -> None:
    driver = _FakeDriver()
    capture_page_source(driver, tmp_path, suffix="_cdn.example_120000",
                        fetch=_ok_fetch({}))
    assert (tmp_path / "page_source_cdn.example_120000.html").is_file()
    assert (tmp_path / "page_source_cdn.example_120000.scripts.json").is_file()


def test_dead_page_source_soft_fails_no_file(tmp_path: Path) -> None:
    driver = _FakeDriver(raise_source=True)
    capture_page_source(driver, tmp_path, suffix="", fetch=_ok_fetch({}))
    assert not (tmp_path / "page_source.html").exists()
    # the index is still written (enumeration may still run)
    assert (tmp_path / "page_source.scripts.json").is_file()


# --- script enumeration + server-side fetch --------------------------------


def test_fetched_body_is_content_addressed(tmp_path: Path) -> None:
    body = b"console.log(1)"
    sha = hashlib.sha256(body).hexdigest()
    driver = _FakeDriver(scripts=[
        {"url": "https://cdn.example/a.js", "integrity": "sha384-x",
         "crossorigin": "anonymous"},
    ])
    capture_page_source(driver, tmp_path, suffix="",
                        fetch=_ok_fetch({"https://cdn.example/a.js": body}))
    assert (tmp_path / "scripts" / sha).read_bytes() == body
    entry = _index(tmp_path)[0]
    assert entry == {
        "url": "https://cdn.example/a.js", "integrity": "sha384-x",
        "crossorigin": "anonymous", "kind": "script",
        "sha256": sha, "status": "200",
    }


def test_unfetchable_body_records_null_sha(tmp_path: Path) -> None:
    driver = _FakeDriver(scripts=[
        {"url": "https://tracker.example/t.js", "integrity": None,
         "crossorigin": None},
    ])
    capture_page_source(driver, tmp_path, suffix="", fetch=_ok_fetch({}))
    entry = _index(tmp_path)[0]
    assert entry["sha256"] is None
    assert entry["status"] == "cors-error"
    assert not (tmp_path / "scripts").exists()


def test_duplicate_bodies_deduped(tmp_path: Path) -> None:
    body = b"shared"
    sha = hashlib.sha256(body).hexdigest()
    driver = _FakeDriver(scripts=[
        {"url": "https://a.example/x.js", "integrity": None, "crossorigin": None},
        {"url": "https://b.example/y.js", "integrity": None, "crossorigin": None},
    ])
    capture_page_source(driver, tmp_path, suffix="", fetch=_ok_fetch({
        "https://a.example/x.js": body, "https://b.example/y.js": body}))
    assert list((tmp_path / "scripts").iterdir()) == [tmp_path / "scripts" / sha]
    assert [e["sha256"] for e in _index(tmp_path)] == [sha, sha]


def test_stylesheet_enumerated_but_not_fetched(tmp_path: Path) -> None:
    """Stylesheets are recorded for SRI analysis (url + integrity +
    crossorigin) but their bodies are not fetched — only script bodies
    are supply-chain inspected."""
    driver = _FakeDriver(scripts=[
        {"url": "https://cdn.example/site.css", "integrity": None,
         "crossorigin": None, "kind": "stylesheet"},
    ])

    def must_not_fetch(url: str):
        raise AssertionError(f"stylesheet body fetched: {url}")

    capture_page_source(driver, tmp_path, suffix="", fetch=must_not_fetch)
    entry = _index(tmp_path)[0]
    assert entry == {
        "url": "https://cdn.example/site.css", "integrity": None,
        "crossorigin": None, "kind": "stylesheet",
        "sha256": None, "status": "not-fetched",
    }
    assert not (tmp_path / "scripts").exists()


def test_entry_without_kind_defaults_to_script(tmp_path: Path) -> None:
    """Robustness: an enumeration record with no ``kind`` is a script
    (every record was, before stylesheets were enumerated)."""
    driver = _FakeDriver(scripts=[
        {"url": "https://cdn.example/a.js", "integrity": None,
         "crossorigin": None},
    ])
    body = b"x"
    capture_page_source(driver, tmp_path, suffix="",
                        fetch=_ok_fetch({"https://cdn.example/a.js": body}))
    assert _index(tmp_path)[0]["kind"] == "script"


def test_enum_failure_yields_empty_index(tmp_path: Path) -> None:
    driver = _FakeDriver(raise_enum=True)
    capture_page_source(driver, tmp_path, suffix="", fetch=_ok_fetch({}))
    assert _index(tmp_path) == []


# --- default fetcher SSRF guard --------------------------------------------
#
# The production fetcher reaches the network for URLs taken verbatim from the
# visited (untrusted) page's ``<script src>`` markup. It must refuse anything
# that is not an http/https URL resolving to a public address — otherwise a
# hostile page could read local files (``file://``) or pull internal / cloud-
# metadata endpoints (SSRF) into the bundle. These cases reject on scheme or
# IP literal alone, so they stay offline.


class _FakeResponse:
    """Context-managed stand-in for an ``http.client`` response."""

    status = 200

    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def read(self, _amount: int) -> bytes:
        return self._body


class _RecordingOpener:
    """Safe-opener double that records calls and returns a fixed body."""

    def __init__(self, body: bytes) -> None:
        self._body = body
        self.opened: list = []

    def open(self, request, timeout=None):
        self.opened.append(request)
        return _FakeResponse(self._body)


def test_default_fetcher_blocks_file_scheme() -> None:
    assert _fetch_script_body("file:///etc/passwd") == (
        None, "blocked-non-public-url")


def test_default_fetcher_blocks_ftp_scheme() -> None:
    assert _fetch_script_body("ftp://cdn.example/a.js") == (
        None, "blocked-non-public-url")


def test_default_fetcher_blocks_loopback() -> None:
    assert _fetch_script_body("http://127.0.0.1/x.js") == (
        None, "blocked-non-public-url")


def test_default_fetcher_blocks_link_local_metadata() -> None:
    assert _fetch_script_body(
        "http://169.254.169.254/latest/meta-data/") == (
        None, "blocked-non-public-url")


def test_default_fetcher_blocks_private_rfc1918() -> None:
    assert _fetch_script_body("http://10.0.0.5:8080/internal.js") == (
        None, "blocked-non-public-url")


def test_default_fetcher_allows_public_url(monkeypatch) -> None:
    # A public IP literal needs no DNS, keeping the pass-through path offline.
    opener = _RecordingOpener(b"console.log(1)")
    monkeypatch.setattr(page_source, "_OPENER", opener)
    assert _fetch_script_body("http://8.8.8.8/a.js") == (b"console.log(1)", "200")
    assert len(opener.opened) == 1