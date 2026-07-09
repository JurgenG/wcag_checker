"""Diff side reports get the analyze-path screenshot-sidecar treatment.

``diff --out DIR`` writes two per-side reports; like ``analyze -o``,
the html/markdown side reports must carry the bundle's screenshots as
sibling lossless-webp files referenced by relative filename (never
``data:`` URIs). Pinned against real fixtures: ``cultuurkuur.zip``
(post-load + four operator shots) vs ``doccle-accept.zip`` (post-load
only). Text diffs stay image-free, mirroring ``analyze``.
"""

from __future__ import annotations

import pytest

from leak_inspector import cli

from tests.fixtures.bundles import path as bundle_path


def _is_webp(data: bytes) -> bool:
    return data[:4] == b"RIFF" and data[8:12] == b"WEBP"


def _run_diff(tmp_path, fmt: str):
    rc = cli.main([
        "diff",
        str(bundle_path("cultuurkuur.zip")),
        str(bundle_path("doccle-accept.zip")),
        "--format", fmt,
        "--out", str(tmp_path),
    ])
    assert rc == 0
    return tmp_path


@pytest.fixture(scope="module")
def html_out(tmp_path_factory):
    return _run_diff(tmp_path_factory.mktemp("diff_html"), "html")


def test_html_side_reports_get_post_load_sidecars(html_out) -> None:
    for stem in ("A.report", "B.report"):
        sidecar = html_out / f"{stem}.post-load.webp"
        assert sidecar.exists(), sidecar
        assert _is_webp(sidecar.read_bytes())


def test_html_side_a_gets_operator_shot_sidecars(html_out) -> None:
    """cultuurkuur (side A) carries four operator-triggered shots."""
    shots = sorted(p.name for p in html_out.glob("A.report.shot_*.webp"))
    assert shots == [
        "A.report.shot_www.cultuurkuur.be_221307.webp",
        "A.report.shot_www.cultuurkuur.be_221349.webp",
        "A.report.shot_www.cultuurkuur.be_221400.webp",
        "A.report.shot_www.cultuurkuur.be_221406.webp",
    ]


def test_html_side_reports_reference_sidecars_not_data_uris(html_out) -> None:
    for stem in ("A.report", "B.report"):
        html = (html_out / f"{stem}.html").read_text(encoding="utf-8")
        assert f"{stem}.post-load.webp" in html
        assert "data:image" not in html


def test_markdown_side_reports_get_sidecars(tmp_path) -> None:
    out = _run_diff(tmp_path, "markdown")
    assert (out / "A.report.post-load.webp").exists()
    assert (out / "B.report.post-load.webp").exists()
    md = (out / "A.report.md").read_text(encoding="utf-8")
    assert "A.report.post-load.webp" in md
    assert "data:image" not in md


def test_text_diff_writes_no_sidecars(tmp_path) -> None:
    out = _run_diff(tmp_path, "text")
    assert list(out.glob("*.webp")) == []
