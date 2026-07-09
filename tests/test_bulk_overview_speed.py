"""The overview must not re-analyze what the bulk run just analyzed.

`build_overview` used to call `analyze_bundle` (live DNS posture +
per-host ASN enrichment + transport probes) for every bundle — a full
second analysis of work `run.py` had just done. Two fixes, both here:

* **Reuse** — `build_overview(analyses={slug: analysis})` consumes the
  analyses the capture loop already produced; provided slugs are never
  re-analyzed. `run.py` collects them from
  `_render_report_from_bundle` (which now returns the analysis).
* **Parallelism** — slugs *not* provided (e.g. `--resume`-skipped
  sites, standalone `overview.py` rebuilds) are analyzed on a thread
  pool: the work is network-bound, so threads cut wall-clock roughly
  by the worker count.
"""

from __future__ import annotations

import shutil
import sys
import threading
from pathlib import Path

import pytest

_BULK_DIR = Path(__file__).resolve().parent.parent / "bulk-tool"
if str(_BULK_DIR) not in sys.path:
    sys.path.insert(0, str(_BULK_DIR))

import overview as overview_module  # noqa: E402
import run as bulk_run  # noqa: E402

from leak_inspector import modules  # noqa: E402,F401  (registers detectors)
from leak_inspector.analysis.runner import analyze_events  # noqa: E402
from leak_inspector.bundle.reader import BundleReader  # noqa: E402

from tests.fixtures.bundles import path as bundle_path  # noqa: E402


def _hermetic(zip_path):
    with BundleReader(zip_path) as b:
        return analyze_events(b.manifest, b.events(), cname_chains=b.cname_chains)


@pytest.fixture
def dataset(tmp_path):
    """Two-bundle dataset (cultuurkuur under two slugs) with reports
    already present, so the overview links resolve."""
    ds = tmp_path / "ds"
    captures = ds / "captures"
    reports = ds / "reports"
    captures.mkdir(parents=True)
    reports.mkdir()
    # NB: real domains.csv files carry no header — a header line would
    # be read as a URL (and the capture path would launch Firefox).
    (ds / "domains.csv").write_text(
        "https://site-a.example\nhttps://site-b.example\n"
    )
    for slug in ("site-a.example", "site-b.example"):
        shutil.copy(bundle_path("cultuurkuur.zip"), captures / f"{slug}.zip")
        (reports / f"{slug}.report.html").write_text("<html/>")
    return ds


def test_provided_analyses_are_not_reanalyzed(dataset, monkeypatch) -> None:
    """Slugs whose analysis is handed in must never hit analyze_bundle."""
    analyses = {
        "site-a.example": _hermetic(dataset / "captures" / "site-a.example.zip"),
        "site-b.example": _hermetic(dataset / "captures" / "site-b.example.zip"),
    }

    def boom(path):
        raise AssertionError(f"re-analyzed {path} despite provided analysis")

    monkeypatch.setattr(overview_module, "analyze_bundle", boom)
    index = overview_module.build_overview(dataset, analyses=analyses)
    assert index is not None
    assert "site-a.example" in index.read_text(encoding="utf-8")


def test_missing_slugs_are_analyzed_on_a_thread_pool(dataset, monkeypatch) -> None:
    """Un-provided slugs still get analyzed — off the main thread."""
    seen_threads: set[str] = set()

    def tracking_analyze(path):
        seen_threads.add(threading.current_thread().name)
        return _hermetic(path)

    monkeypatch.setattr(overview_module, "analyze_bundle", tracking_analyze)
    index = overview_module.build_overview(dataset)
    assert index is not None
    assert seen_threads, "analyze_bundle never called for missing slugs"
    assert all("MainThread" != t for t in seen_threads)


def test_summary_order_is_deterministic(dataset, monkeypatch) -> None:
    """Thread completion order must not shuffle the overview rows."""
    monkeypatch.setattr(overview_module, "analyze_bundle", _hermetic)
    index = overview_module.build_overview(dataset)
    html = index.read_text(encoding="utf-8")
    assert html.index("site-a.example") < html.index("site-b.example")


def test_run_collects_and_passes_analyses(dataset, monkeypatch) -> None:
    """The bulk runner hands its per-site analyses to build_overview so
    nothing is analyzed twice in a normal run."""
    monkeypatch.setattr(bulk_run, "analyze_bundle", _hermetic)
    received: dict = {}

    def fake_overview(
        dataset_dir, reports_dir=None, analyses=None, report_format="html"
    ):
        received["analyses"] = analyses
        return None

    monkeypatch.setattr(bulk_run, "build_overview", fake_overview)
    # --resume with reports missing → render path runs (no Firefox).
    for slug in ("site-a.example", "site-b.example"):
        (dataset / "reports" / f"{slug}.report.html").unlink()
    rc = bulk_run.main([str(dataset), "--resume"])
    assert rc == 0
    assert received["analyses"] is not None
    assert set(received["analyses"]) == {"site-a.example", "site-b.example"}
