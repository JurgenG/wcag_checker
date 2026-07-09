"""Tests for sidecar-screenshot output (`analyze -o FILE`).

When the report is written to a file, screenshots are written as
sibling images next to it and referenced by relative filename — instead
of being inlined as base64 ``data:`` URIs (the stdout default). Sidecars
are converted PNG → lossless webp (bit-exact pixels, ~60-70 % smaller
on flat-color page screenshots); the bundle keeps the archival PNG.
Pinned against `cultuurkuur.zip`, which carries a canonical post-load
shot plus four operator-triggered screenshots.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from leak_inspector.bundle.reader import BundleReader
from leak_inspector.report.screenshots import (
    png_to_webp,
    sidecar_screenshot_name as _sidecar_screenshot_name,
    write_screenshot_sidecars as _write_screenshot_sidecars,
)

from tests.fixtures.bundles import path as bundle_path


def _is_webp(data: bytes) -> bool:
    return data[:4] == b"RIFF" and data[8:12] == b"WEBP"


# --- the conversion helper ---------------------------------------------------


def test_png_to_webp_is_lossless_webp() -> None:
    """Conversion produces a real webp, losslessly (pixels bit-exact)."""
    from io import BytesIO

    from PIL import Image

    with BundleReader(bundle_path("cultuurkuur.zip")) as bundle:
        png = bundle.screenshot_bytes
    webp = png_to_webp(png)
    assert _is_webp(webp)
    assert len(webp) < len(png)  # the point of the exercise
    original = Image.open(BytesIO(png)).convert("RGBA")
    roundtrip = Image.open(BytesIO(webp)).convert("RGBA")
    assert original.tobytes() == roundtrip.tobytes()


# --- the pure naming helper -------------------------------------------------


def test_sidecar_name_canonical_is_post_load() -> None:
    assert _sidecar_screenshot_name("awel-be", None, 0) == "awel-be.post-load.webp"


def test_sidecar_name_manual_keeps_host_and_time() -> None:
    name = _sidecar_screenshot_name(
        "awel-be", "screenshot_g.awel.be_174812.png", 1
    )
    assert name == "awel-be.shot_g.awel.be_174812.webp"


def test_sidecar_name_manual_falls_back_to_index() -> None:
    """A recorder name that doesn't match ``_<host>_<HHMMSS>`` still gets
    a stable, collision-free sidecar name."""
    name = _sidecar_screenshot_name("awel-be", "weird-name.png", 3)
    assert name == "awel-be.shot-3.webp"


# --- end-to-end sidecar writing ---------------------------------------------


@pytest.fixture
def written(tmp_path):
    """Write cultuurkuur's screenshots as sidecars and return the result."""
    with BundleReader(bundle_path("cultuurkuur.zip")) as bundle:
        canonical, extras, captions = _write_screenshot_sidecars(
            bundle, out_dir=tmp_path, stem="cultuurkuur",
        )
    return tmp_path, canonical, extras, captions


def test_canonical_sidecar_written_and_named(written) -> None:
    tmp_path, canonical, _, _ = written
    assert canonical == "cultuurkuur.post-load.webp"
    f = tmp_path / canonical
    assert f.exists()
    assert _is_webp(f.read_bytes())  # real webp file, not a URI


def test_manual_sidecars_written_with_host_time_names(written) -> None:
    tmp_path, _, extras, _ = written
    assert extras == [
        "cultuurkuur.shot_www.cultuurkuur.be_221307.webp",
        "cultuurkuur.shot_www.cultuurkuur.be_221349.webp",
        "cultuurkuur.shot_www.cultuurkuur.be_221400.webp",
        "cultuurkuur.shot_www.cultuurkuur.be_221406.webp",
    ]
    for name in extras:
        assert _is_webp((tmp_path / name).read_bytes())


def test_captions_preserved(written) -> None:
    _, _, _, captions = written
    assert len(captions) == 4
    assert "www.cultuurkuur.be @ 22:13:07" in captions[0]


def test_no_data_uris_anywhere(written) -> None:
    """The whole point: file output references files, never data: URIs."""
    _, canonical, extras, _ = written
    for ref in [canonical, *extras]:
        assert not ref.startswith("data:")
        assert ref.endswith(".webp")
