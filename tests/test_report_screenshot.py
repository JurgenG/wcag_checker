"""Tests for the ``analyze`` CLI's screenshot-embedding behaviour.

These are data-flow tests, not render tests: the HTML CLI must walk
the bundle, convert every PNG it finds to lossless webp, base64-encode
it, and emit a self-contained HTML where screenshots already appear
(no sibling files needed). The JSON CLI must NOT embed images — it
stays a structured representation.

Per-format markup details (where the figure goes, what class names
it carries, how the layout is ordered) are presentation choices and
deliberately not pinned here.
"""

from __future__ import annotations

import argparse
import base64
import io
import shutil
import zipfile
from contextlib import redirect_stdout
from leak_inspector.cli import _do_analyze
from leak_inspector.report.screenshots import png_to_webp

from tests.fixtures.bundles import path as bundle_path


_REAL_BUNDLE = bundle_path("nbb.zip")


def _tiny_png(rgb: tuple[int, int, int]) -> bytes:
    """A real (decodable) 2×2 PNG — the webp conversion needs valid pixels."""
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (2, 2), rgb).save(buf, format="PNG")
    return buf.getvalue()


def test_analyze_cli_embeds_screenshots_as_data_uris(tmp_path) -> None:
    """The ``analyze`` CLI walks the bundle and embeds each screenshot
    as a base64 webp ``data:`` URI so a redirected-stdout invocation
    produces a self-contained HTML — no sibling files needed."""
    target = tmp_path / "test.zip"
    shutil.copy(_REAL_BUNDLE, target)

    canonical_png = _tiny_png((255, 0, 0))
    extra_png = _tiny_png((0, 0, 255))
    with zipfile.ZipFile(target, "a") as z:
        z.writestr("screenshot.png", canonical_png)
        z.writestr("screenshot_x.be_120000.png", extra_png)

    args = argparse.Namespace(
        bundle=target, format="html", no_color=True,
        verbose=False, debug=False,
    )
    out = io.StringIO()
    with redirect_stdout(out):
        rc = _do_analyze(args)
    assert rc == 0
    html = out.getvalue()

    canonical_b64 = base64.b64encode(png_to_webp(canonical_png)).decode("ascii")
    extra_b64 = base64.b64encode(png_to_webp(extra_png)).decode("ascii")
    assert f"data:image/webp;base64,{canonical_b64}" in html
    assert f"data:image/webp;base64,{extra_b64}" in html
    assert "data:image/png" not in html  # everything converted


def test_analyze_cli_json_does_not_embed_screenshots(tmp_path) -> None:
    """JSON output stays a clean structured representation — no
    screenshot embedding."""
    target = tmp_path / "test.zip"
    shutil.copy(_REAL_BUNDLE, target)
    png = b"FAKE-PNG"
    with zipfile.ZipFile(target, "a") as z:
        z.writestr("screenshot.png", png)

    args = argparse.Namespace(
        bundle=target, format="json", no_color=True,
        verbose=False, debug=False,
    )
    out = io.StringIO()
    with redirect_stdout(out):
        rc = _do_analyze(args)
    assert rc == 0
    assert "data:image" not in out.getvalue()
