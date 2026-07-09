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

"""Write a bundle's screenshots as sidecar webp files next to a report.

Shared by the ``analyze -o FILE`` CLI path and the bulk runner so both
emit the same logical filenames and relative ``<img>`` references
instead of inlining base64 ``data:`` URIs. ``stem`` is the report
filename without extension; for ``out/awel.html`` it is ``awel`` and
for the bulk runner's ``aalst.be.report.html`` it is
``aalst.be.report`` — the convention composes either way.

The bundle keeps storing archival PNG (bit-exact, schema untouched);
the report-side copies are converted to **lossless** webp — pixels
stay identical (these are evidence) while flat-color page screenshots
shrink by roughly 60-70 %.
"""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

from PIL import Image

from .html import _caption_from_extra_screenshot


def png_to_webp(png_bytes: bytes) -> bytes:
    """Convert PNG bytes to lossless webp bytes.

    Lossless keeps the screenshot bit-exact (it's evidence, not
    decoration) and still beats lossy on flat-color page captures.
    """
    out = BytesIO()
    Image.open(BytesIO(png_bytes)).save(out, format="WEBP", lossless=True)
    return out.getvalue()


def sidecar_screenshot_name(stem: str, bundle_name: str | None, index: int) -> str:
    """Logical filename for one screenshot written next to the report.

    ``bundle_name is None`` → the canonical post-load shot, named
    ``<stem>.post-load.webp``. Otherwise an operator-triggered shot:
    the recorder writes ``screenshot_<host>_<HHMMSS>.png``, which
    becomes ``<stem>.shot_<host>_<HHMMSS>.webp`` (host + time
    preserved). Names that don't match that shape fall back to
    ``<stem>.shot-<n>.webp`` so the result is always stable and
    collision-free.
    """
    if bundle_name is None:
        return f"{stem}.post-load.webp"
    base = bundle_name.rsplit("/", 1)[-1]
    if base.endswith(".png"):
        base = base[: -len(".png")]
    parts = base.split("_")
    if len(parts) >= 3 and parts[-1].isdigit() and len(parts[-1]) == 6:
        host, hhmmss = parts[-2], parts[-1]
        return f"{stem}.shot_{host}_{hhmmss}.webp"
    return f"{stem}.shot-{index}.webp"


def write_screenshot_sidecars(
    bundle, *, out_dir: Path, stem: str
) -> tuple[str | None, list[str], list[str]]:
    """Write the bundle's screenshots as lossless-webp files into ``out_dir``.

    Converts the canonical post-load shot and every operator-triggered
    shot from the bundle's archival PNG and writes them under the
    :func:`sidecar_screenshot_name` convention. Returns
    ``(canonical_name_or_None, [extra_names…], [captions…])`` — relative
    filenames the report writers drop into ``<img src>`` / ``![](…)``
    directly, plus a human caption per extra shot.
    """
    canonical: str | None = None
    extras: list[str] = []
    captions: list[str] = []
    png = bundle.screenshot_bytes
    if png:
        canonical = sidecar_screenshot_name(stem, None, 0)
        (out_dir / canonical).write_bytes(png_to_webp(png))
    for index, (name, body) in enumerate(bundle.extra_screenshots(), start=1):
        sidecar = sidecar_screenshot_name(stem, name, index)
        (out_dir / sidecar).write_bytes(png_to_webp(body))
        extras.append(sidecar)
        captions.append(_caption_from_extra_screenshot(name))
    return canonical, extras, captions


__all__ = ["png_to_webp", "sidecar_screenshot_name", "write_screenshot_sidecars"]
