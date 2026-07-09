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

"""Bundle writer.

Given a finished session directory (populated by the capture layer) and a
:class:`Manifest`, write the manifest to disk, zip the directory, and
optionally remove the working tree.

The writer is pure I/O. It does not interpret events or storage payloads;
it only guarantees the zip is well-formed and the manifest validates.
"""

from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

from .manifest import Manifest, ManifestError


class BundleWriteError(RuntimeError):
    """Raised when a session directory is not in a valid shape to zip."""


def write_bundle(
    session_dir: Path,
    manifest: Manifest,
    out_path: Path,
    *,
    cleanup: bool = True,
) -> Path:
    """Finalize a capture session into a bundle zip on disk.

    Steps, in order:

    1. Validate ``manifest`` round-trips through ``from_dict`` (fail loudly
       on missing or malformed fields before producing any output).
    2. Write ``manifest.json`` into ``session_dir``.
    3. Verify ``events.jsonl`` exists in ``session_dir``.
    4. Zip the entire ``session_dir`` to ``out_path`` (overwriting if
       present).
    5. If ``cleanup`` is true, remove ``session_dir`` recursively.

    Returns the absolute path to the produced zip.
    """
    session_dir = Path(session_dir)
    out_path = Path(out_path)

    if not session_dir.is_dir():
        raise BundleWriteError(f"session_dir does not exist: {session_dir}")

    try:
        Manifest.from_dict(manifest.to_dict())
    except ManifestError as exc:
        raise BundleWriteError(f"manifest failed validation: {exc}") from exc

    manifest_path = session_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )

    events_path = session_dir / "events.jsonl"
    if not events_path.is_file():
        raise BundleWriteError(
            f"session_dir is missing events.jsonl: {events_path}"
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    _zip_directory(session_dir, out_path)

    if cleanup:
        shutil.rmtree(session_dir)

    return out_path.resolve()


def _zip_directory(src: Path, dest: Path) -> None:
    """Zip every file under ``src`` into ``dest`` with deterministic ordering."""
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(p for p in src.rglob("*") if p.is_file()):
            zf.write(path, arcname=path.relative_to(src).as_posix())


__all__ = [
    "BundleWriteError",
    "write_bundle",
]