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

"""Bundle reader.

A :class:`BundleReader` opens a capture-produced zip and exposes the four
things analysis needs:

* the parsed :class:`Manifest`,
* a streaming iterator over events,
* lazy access to per-origin storage snapshots,
* lazy access to content-addressed script bodies.

The reader does not extract the zip; everything is read on demand from
the archive.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Iterator

from ..events import Event, parse_event
from .manifest import Manifest


# --- size caps (anti-zip-bomb) ---------------------------------------------
#
# A zip can compress 1 GB of zeros to 1 MB on disk. Without these caps,
# ``raw.read()`` on the inflated entry OOMs the analyst on bundle open.
# Likewise a single 10 GB JSONL line inside ``events.jsonl`` defeats
# the line-streaming defence — bounded ``readline`` blocks that vector.
#
# Caps are set ~50× the largest real-world value observed in our
# fixture bundles (manifests <500 B, events lines <100 KB, storage
# <200 KB, screenshots ~1 MB). Anything past the cap is hostile.

#: Per-entry cap on ``manifest.json`` uncompressed size.
_MAX_MANIFEST_BYTES = 1 * 1024 * 1024  # 1 MB (typical: <1 KB)

#: Per-entry cap on ``cname_chains.json`` uncompressed size.
_MAX_CNAME_BYTES = 1 * 1024 * 1024  # 1 MB (typical: <10 KB)

#: Per-entry cap on ``enrichment.json`` uncompressed size.
_MAX_ENRICHMENT_BYTES = 4 * 1024 * 1024  # 4 MB (typical: <100 KB)

#: Per-entry cap on ``storage/<origin>.json`` uncompressed size.
_MAX_STORAGE_BYTES = 16 * 1024 * 1024  # 16 MB (typical: <500 KB)

#: Per-entry cap on ``scripts/<sha256>`` uncompressed size.
_MAX_SCRIPT_BYTES = 16 * 1024 * 1024  # 16 MB (typical: <2 MB)

#: Per-entry cap on screenshot PNG files.
_MAX_SCREENSHOT_BYTES = 64 * 1024 * 1024  # 64 MB (typical: <2 MB)

#: Per-entry cap on ``page_source*.html`` files. Rendered DOM can be
#: large; sized well above the largest real pages observed.
_MAX_PAGE_SOURCE_BYTES = 32 * 1024 * 1024  # 32 MB (typical: <2 MB)

#: Cap on the total uncompressed size of ``events.jsonl``. Above this
#: the bundle is rejected outright — no streaming benefit can recover
#: a multi-GB events file. Set very generously (1 GB).
_MAX_EVENTS_FILE_BYTES = 1 * 1024 * 1024 * 1024  # 1 GB

#: Per-line cap on ``events.jsonl``. A line beyond this is dropped and
#: counted on the reader's :attr:`BundleReader.truncated_events`.
_MAX_EVENT_LINE_BYTES = 4 * 1024 * 1024  # 4 MB (typical: <100 KB)


class BundleReadError(RuntimeError):
    """Raised when a bundle zip is malformed or missing required entries."""


class BundleReader:
    """Open a bundle zip and read its contents lazily.

    Use as a context manager::

        with BundleReader(path) as bundle:
            for event in bundle.events():
                ...
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._zip: zipfile.ZipFile | None = None
        self._manifest: Manifest | None = None
        #: Count of ``events.jsonl`` lines dropped because they exceeded
        #: ``_MAX_EVENT_LINE_BYTES``. Surfaced so analysis can warn the
        #: operator instead of silently under-counting events.
        self.truncated_events: int = 0

    def __enter__(self) -> "BundleReader":
        self._zip = zipfile.ZipFile(self.path, "r")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._zip is not None:
            self._zip.close()
            self._zip = None

    @property
    def manifest(self) -> Manifest:
        """Return the parsed manifest, reading it from the zip on first access."""
        if self._manifest is None:
            data = self._read_json("manifest.json", cap=_MAX_MANIFEST_BYTES)
            self._manifest = Manifest.from_dict(data)
        return self._manifest

    def events(self) -> Iterator[Event]:
        """Yield parsed events from ``events.jsonl`` in file order.

        Lines that fail to parse raise :class:`EventParseError` from the
        events module; callers may catch that to skip-with-warning.

        Pathologically large bundles are refused: a total uncompressed
        ``events.jsonl`` exceeding ``_MAX_EVENTS_FILE_BYTES`` raises
        :class:`BundleReadError` before iteration starts. Per-line bombs
        are dropped silently and counted on :attr:`truncated_events` so
        analysis can surface "N events skipped due to size cap" without
        OOMing on a single bomb line.
        """
        zf = self._require_open()
        try:
            info = zf.getinfo("events.jsonl")
        except KeyError as exc:
            raise BundleReadError("bundle missing events.jsonl") from exc
        if info.file_size > _MAX_EVENTS_FILE_BYTES:
            raise BundleReadError(
                f"events.jsonl uncompressed size {info.file_size} "
                f"exceeds cap of {_MAX_EVENTS_FILE_BYTES} bytes"
            )

        with zf.open(info, "r") as raw:
            # ``readline(N+1)`` returns up to N+1 bytes OR up to the next
            # newline, whichever comes first. If the returned chunk is
            # > N bytes, the line was bigger than the cap — drain the
            # rest of the line so subsequent lines resynchronize.
            cap = _MAX_EVENT_LINE_BYTES
            while True:
                line = raw.readline(cap + 1)
                if not line:
                    break
                if len(line) > cap:
                    self.truncated_events += 1
                    # Drain remainder of this line up to the next newline,
                    # capping each chunk so we still defeat the OOM.
                    while line and not line.endswith(b"\n"):
                        line = raw.readline(cap + 1)
                    continue
                stripped = line.strip()
                if not stripped:
                    continue
                yield parse_event(json.loads(stripped))

    @property
    def cname_chains(self) -> dict[str, list[str]]:
        """Return the per-host CNAME chains captured at session-end.

        Each value is a list ``[input_host, …, canonical]``. A single-
        element list means no CNAME (or DNS failure at capture time).
        Returns an empty dict if the bundle was produced by a build
        that did not collect chains — backward-compatible.
        """
        zf = self._require_open()
        try:
            info = zf.getinfo("cname_chains.json")
        except KeyError:
            return {}
        if info.file_size > _MAX_CNAME_BYTES:
            raise BundleReadError(
                f"cname_chains.json uncompressed size {info.file_size} "
                f"exceeds cap of {_MAX_CNAME_BYTES} bytes"
            )
        with zf.open(info, "r") as raw:
            data = json.loads(raw.read().decode("utf-8"))
        if not isinstance(data, dict):
            return {}
        result: dict[str, list[str]] = {}
        for host, chain in data.items():
            if isinstance(host, str) and isinstance(chain, list):
                result[host.lower()] = [
                    str(item).lower() for item in chain if isinstance(item, str)
                ]
        return result

    @property
    def enrichment(self):
        """Return the bundle's stored enrichment, or ``None`` when absent.

        The artifact is written by the enrichment phase (at capture
        close, or retrofitted via ``leak-inspector enrich``) as the
        ``enrichment.json`` zip entry. Bundles produced before the
        enrichment phase existed simply return ``None`` —
        backward-compatible, like :attr:`cname_chains`.

        The import is lazy and acyclic: :mod:`..enrichment.artifact`
        is pure data (it never imports ``bundle``); only the producer
        side reads bundles.
        """
        from ..enrichment.artifact import (
            ENRICHMENT_ZIP_ENTRY,
            enrichment_from_json,
        )

        zf = self._require_open()
        try:
            info = zf.getinfo(ENRICHMENT_ZIP_ENTRY)
        except KeyError:
            return None
        if info.file_size > _MAX_ENRICHMENT_BYTES:
            raise BundleReadError(
                f"{ENRICHMENT_ZIP_ENTRY} uncompressed size {info.file_size} "
                f"exceeds cap of {_MAX_ENRICHMENT_BYTES} bytes"
            )
        with zf.open(info, "r") as raw:
            return enrichment_from_json(raw.read().decode("utf-8"))

    @property
    def screenshot_bytes(self) -> bytes | None:
        """Return the post-load page screenshot as raw PNG bytes.

        Returns ``None`` when the bundle was produced by a build that
        did not capture screenshots, or when the capture failed (e.g.
        the WebDriver session ended before the screenshot could be
        taken). Backward-compatible with old bundles.
        """
        zf = self._require_open()
        try:
            info = zf.getinfo("screenshot.png")
        except KeyError:
            return None
        if info.file_size > _MAX_SCREENSHOT_BYTES:
            raise BundleReadError(
                f"screenshot.png uncompressed size {info.file_size} "
                f"exceeds cap of {_MAX_SCREENSHOT_BYTES} bytes"
            )
        with zf.open(info, "r") as raw:
            return raw.read()

    def extra_screenshots(self) -> Iterator[tuple[str, bytes]]:
        """Yield operator-triggered screenshots as ``(name, bytes)`` pairs.

        These are the PNGs the recorder wrote when the operator pressed
        the in-session screenshot shortcut — file names follow the shape
        ``screenshot_<host>_<HHMMSS>.png``. Returned sorted by name so
        consumers get a chronological order (the ``HHMMSS`` suffix is
        zero-padded, so lexicographic sort matches time order).

        The canonical post-load ``screenshot.png`` is *not* included —
        callers fetch that via :attr:`screenshot_bytes`.
        """
        zf = self._require_open()
        names = sorted(
            n for n in zf.namelist()
            if n.startswith("screenshot_") and n.endswith(".png") and "/" not in n
        )
        for name in names:
            info = zf.getinfo(name)
            if info.file_size > _MAX_SCREENSHOT_BYTES:
                raise BundleReadError(
                    f"{name} uncompressed size {info.file_size} "
                    f"exceeds cap of {_MAX_SCREENSHOT_BYTES} bytes"
                )
            with zf.open(info, "r") as raw:
                yield name, raw.read()

    def page_source(self, name: str = "page_source.html") -> str | None:
        """Return a saved page-source HTML document, or ``None`` when absent.

        Capture writes ``page_source.html`` (post-load) and
        ``page_source_<host>_<HHMMSS>.html`` (operator-triggered) verbatim
        alongside each screenshot. ``name`` selects which one; the default
        is the canonical post-load document. Raises :class:`BundleReadError`
        if the entry exceeds :data:`_MAX_PAGE_SOURCE_BYTES`.
        """
        zf = self._require_open()
        try:
            info = zf.getinfo(name)
        except KeyError:
            return None
        if info.file_size > _MAX_PAGE_SOURCE_BYTES:
            raise BundleReadError(
                f"{name} uncompressed size {info.file_size} "
                f"exceeds cap of {_MAX_PAGE_SOURCE_BYTES} bytes"
            )
        with zf.open(info, "r") as raw:
            return raw.read().decode("utf-8")

    def page_sources(self) -> Iterator[tuple[str, str]]:
        """Yield every saved page-source document as ``(name, html)``.

        Covers both the canonical ``page_source.html`` and the
        operator-triggered ``page_source_<host>_<HHMMSS>.html`` files,
        sorted by name (chronological for the zero-padded suffix).
        """
        zf = self._require_open()
        names = sorted(
            n for n in zf.namelist()
            if n.startswith("page_source") and n.endswith(".html") and "/" not in n
        )
        for name in names:
            yield name, self.page_source(name)

    def page_source_scripts(
        self, name: str = "page_source.scripts.json",
    ) -> list[dict] | None:
        """Return the script index for a page source, or ``None`` when absent.

        Each entry is ``{url, integrity, crossorigin, sha256, status}``;
        a non-null ``sha256`` resolves to the body via :meth:`script`.
        ``name`` mirrors the page-source basename
        (``page_source{suffix}.scripts.json``).
        """
        try:
            return self._read_json(name, cap=_MAX_PAGE_SOURCE_BYTES)
        except KeyError:
            return None

    def page_source_script_indexes(self) -> Iterator[tuple[str, list[dict]]]:
        """Yield every saved script index as ``(name, entries)``.

        Covers the canonical ``page_source.scripts.json`` and any
        operator-triggered ``page_source_<host>_<HHMMSS>.scripts.json``,
        sorted by name (chronological for the zero-padded suffix). Empty
        when the bundle predates page-source capture.
        """
        zf = self._require_open()
        names = sorted(
            n for n in zf.namelist()
            if n.startswith("page_source") and n.endswith(".scripts.json")
            and "/" not in n
        )
        for name in names:
            yield name, self.page_source_scripts(name)

    def storage_origins(self) -> list[str]:
        """Return the origin stems of every ``storage/<origin>.json`` file.

        Sorted for stable, diff-friendly order. Each stem is the value the
        :meth:`storage` accessor expects, so callers can enumerate
        per-origin snapshots without reconstructing filenames from the
        scheme-qualified origins recorded in the event stream. Empty when
        the bundle carries no storage snapshots.
        """
        zf = self._require_open()
        stems = [
            n[len("storage/"):-len(".json")]
            for n in zf.namelist()
            if n.startswith("storage/") and n.endswith(".json")
            and "/" not in n[len("storage/"):]
        ]
        return sorted(stems)

    def storage(self, origin: str) -> dict:
        """Return the storage snapshot file for ``origin``.

        The on-disk shape is whatever capture wrote into
        ``storage/<origin>.json``. Raises :class:`BundleReadError` if no
        snapshot exists for that origin.
        """
        name = f"storage/{origin}.json"
        try:
            return self._read_json(name, cap=_MAX_STORAGE_BYTES)
        except KeyError as exc:
            raise BundleReadError(f"no storage snapshot for origin {origin!r}") from exc

    def script(self, sha256: str) -> bytes:
        """Return the raw bytes of the content-addressed script ``sha256``."""
        zf = self._require_open()
        name = f"scripts/{sha256}"
        try:
            info = zf.getinfo(name)
        except KeyError as exc:
            raise BundleReadError(f"no script with sha256 {sha256!r}") from exc
        if info.file_size > _MAX_SCRIPT_BYTES:
            raise BundleReadError(
                f"{name} uncompressed size {info.file_size} "
                f"exceeds cap of {_MAX_SCRIPT_BYTES} bytes"
            )
        with zf.open(info, "r") as raw:
            return raw.read()

    def _read_json(self, name: str, *, cap: int) -> dict:
        """Read and JSON-decode a named entry from the zip, capped at ``cap`` bytes.

        Raises :class:`BundleReadError` if the uncompressed entry size
        exceeds ``cap``. Raises :class:`KeyError` if the entry is
        missing (callers wrap that with a more specific message).
        """
        zf = self._require_open()
        info = zf.getinfo(name)  # may raise KeyError; propagated to caller
        if info.file_size > cap:
            raise BundleReadError(
                f"{name} uncompressed size {info.file_size} "
                f"exceeds cap of {cap} bytes"
            )
        with zf.open(info, "r") as raw:
            return json.loads(raw.read().decode("utf-8"))

    def _require_open(self) -> zipfile.ZipFile:
        if self._zip is None:
            raise BundleReadError(
                "BundleReader used outside of its context manager"
            )
        return self._zip


__all__ = [
    "BundleReadError",
    "BundleReader",
]