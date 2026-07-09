"""The bulk runner writes screenshots with the shared sidecar naming.

`bulk-tool/run.py` and `analyze -o FILE` must emit the same logical
filenames so a dataset's per-site reports are consistent. Pinned
against `cultuurkuur.zip` (canonical + operator-triggered shots).

`_render_report_from_bundle` calls `analyze_bundle`, which probes the
network for transport/DNS posture — monkeypatched here to a hermetic
`analyze_events` so the test stays offline and deterministic.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BULK_DIR = Path(__file__).resolve().parent.parent / "bulk-tool"
if str(_BULK_DIR) not in sys.path:
    sys.path.insert(0, str(_BULK_DIR))

import run as bulk_run  # noqa: E402

from leak_inspector import modules  # noqa: E402,F401  (registers detectors)
from leak_inspector.analysis.runner import analyze_events  # noqa: E402
from leak_inspector.bundle.reader import BundleReader  # noqa: E402

from tests.fixtures.bundles import path as bundle_path  # noqa: E402


def _hermetic(zip_path):
    with BundleReader(zip_path) as b:
        return analyze_events(b.manifest, b.events(), cname_chains=b.cname_chains)


@pytest.fixture
def rendered(tmp_path, monkeypatch):
    monkeypatch.setattr(bulk_run, "analyze_bundle", _hermetic)
    report = tmp_path / "www.cultuurkuur.be.report.html"
    bulk_run._render_report_from_bundle(
        bundle_path("cultuurkuur.zip"), report, report_format="html",
    )
    return tmp_path, report


def test_canonical_sidecar_uses_post_load_name(rendered) -> None:
    tmp_path, _ = rendered
    f = tmp_path / "www.cultuurkuur.be.report.post-load.webp"
    assert f.exists()
    data = f.read_bytes()
    assert data[:4] == b"RIFF" and data[8:12] == b"WEBP"


def test_manual_sidecars_use_shot_host_time_name(rendered) -> None:
    tmp_path, _ = rendered
    shots = sorted(
        p.name for p in tmp_path.iterdir()
        if p.name.startswith("www.cultuurkuur.be.report.shot_")
    )
    assert shots == [
        "www.cultuurkuur.be.report.shot_www.cultuurkuur.be_221307.webp",
        "www.cultuurkuur.be.report.shot_www.cultuurkuur.be_221349.webp",
        "www.cultuurkuur.be.report.shot_www.cultuurkuur.be_221400.webp",
        "www.cultuurkuur.be.report.shot_www.cultuurkuur.be_221406.webp",
    ]


def test_report_links_relatively_not_embedded(rendered) -> None:
    _, report = rendered
    html = report.read_text(encoding="utf-8")
    assert 'src="www.cultuurkuur.be.report.post-load.webp"' in html
    assert "data:image" not in html  # relative links, never base64


def test_bulk_report_carries_consent_status(rendered) -> None:
    """Every bulk report states the cookie-consent status — here the
    capture recorded an explicit reject."""
    _, report = rendered
    html = report.read_text(encoding="utf-8")
    assert "Consent: visitor rejected" in html
