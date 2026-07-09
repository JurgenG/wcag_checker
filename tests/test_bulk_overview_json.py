"""The bulk overview writes a structured index.json for --format json runs.

For a json dataset the overview's main artifact is ``index.json``, not
``index.html``: a machine-readable rollup carrying the same information the
HTML overview shows (dataset name, best/worst rankings, cross-site common
findings, government / para-gov reach, and the full per-site list with
scores). Per-site links point at the ``<slug>.report.json`` documents.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

_BULK_DIR = Path(__file__).resolve().parent.parent / "bulk-tool"
if str(_BULK_DIR) not in sys.path:
    sys.path.insert(0, str(_BULK_DIR))

import overview as overview_module  # noqa: E402

from leak_inspector import modules  # noqa: E402,F401  (registers detectors)
from leak_inspector.analysis.runner import analyze_events  # noqa: E402
from leak_inspector.bundle.reader import BundleReader  # noqa: E402
from leak_inspector.report.score_v2 import DimensionView, ScoreView  # noqa: E402

from tests.fixtures.bundles import path as bundle_path  # noqa: E402


def _hermetic(zip_path):
    with BundleReader(zip_path) as b:
        return analyze_events(b.manifest, b.events(), cname_chains=b.cname_chains)


@pytest.fixture
def json_dataset(tmp_path):
    """Two-bundle dataset whose per-site reports are ``.report.json`` files."""
    ds = tmp_path / "ds"
    captures = ds / "captures"
    reports = ds / "reports"
    captures.mkdir(parents=True)
    reports.mkdir()
    (ds / "domains.csv").write_text(
        "https://site-a.example\nhttps://site-b.example\n"
    )
    for slug in ("site-a.example", "site-b.example"):
        shutil.copy(bundle_path("cultuurkuur.zip"), captures / f"{slug}.zip")
        (reports / f"{slug}.report.json").write_text("{}")
    return ds


def _analyses(ds):
    return {
        slug: _hermetic(ds / "captures" / f"{slug}.zip")
        for slug in ("site-a.example", "site-b.example")
    }


# --- build_overview integration ------------------------------------------


def test_json_format_writes_index_json(json_dataset) -> None:
    """--format json → the overview file is index.json, not index.html."""
    index = overview_module.build_overview(
        json_dataset, analyses=_analyses(json_dataset), report_format="json",
    )
    assert index is not None
    assert index.name == "index.json"
    assert not (json_dataset / "reports" / "index.html").exists()


def test_index_json_is_valid_and_has_expected_keys(json_dataset) -> None:
    index = overview_module.build_overview(
        json_dataset, analyses=_analyses(json_dataset), report_format="json",
    )
    payload = json.loads(index.read_text(encoding="utf-8"))
    for key in (
        "dataset", "site_count", "rankings", "common_findings",
        "government_third_parties", "paragov_third_parties", "sites",
    ):
        assert key in payload
    assert payload["site_count"] == 2


def test_index_json_links_per_site_json_reports(json_dataset) -> None:
    """Sites are discovered via their .report.json files and linked as such."""
    index = overview_module.build_overview(
        json_dataset, analyses=_analyses(json_dataset), report_format="json",
    )
    payload = json.loads(index.read_text(encoding="utf-8"))
    slugs = {site["slug"] for site in payload["sites"]}
    assert slugs == {"site-a.example", "site-b.example"}
    for site in payload["sites"]:
        assert site["report"] == f"{site['slug']}.report.json"


def test_default_format_still_writes_index_html(json_dataset) -> None:
    """Regression: the default (html) path keeps writing index.html."""
    reports = json_dataset / "reports"
    for slug in ("site-a.example", "site-b.example"):
        (reports / f"{slug}.report.html").write_text("<html/>")
    index = overview_module.build_overview(
        json_dataset, analyses=_analyses(json_dataset),
    )
    assert index.name == "index.html"


# --- _render_overview_json data shape -------------------------------------


def _score(total: int) -> ScoreView:
    dim = DimensionView(
        stars=total, max_stars=100, rationale="x", penalty=0.0, deductions=()
    )
    return ScoreView(
        resilience=dim, security=dim, privacy=dim,
        total=total, max_total=100, top_action=None,
    )


def _summary(
    slug: str,
    *,
    score: ScoreView | None = None,
    gov: dict | None = None,
    paragov: dict | None = None,
    high: int = 0,
    trackers: int = 0,
    headlines=(),
):
    from overview import SiteSummary

    return SiteSummary(
        slug=slug,
        target_url=f"https://{slug}/",
        landing_url=f"https://{slug}/",
        report_filename=f"{slug}.report.json",
        high_finding_count=high,
        medium_finding_count=0,
        low_finding_count=0,
        total_high_impact_fields=0,
        trackers_fired=trackers,
        third_party_hosts_touched=0,
        finding_headlines=list(headlines),
        gov_hosts_by_level=gov or {},
        paragov_hosts_by_vendor=paragov or {},
        score=score,
    )


def test_render_json_serializes_scores_and_orders_sites_best_first() -> None:
    summaries = [
        _summary("low.example", score=_score(40)),
        _summary("high.example", score=_score(90)),
    ]
    payload = json.loads(overview_module._render_overview_json("ds", summaries))
    sites = payload["sites"]
    assert [s["slug"] for s in sites] == ["high.example", "low.example"]
    assert sites[0]["score"] == {
        "total": 90, "resilience": 90, "security": 90, "privacy": 90,
    }


def test_render_json_unscored_site_has_null_score() -> None:
    payload = json.loads(
        overview_module._render_overview_json("ds", [_summary("a.example")])
    )
    assert payload["sites"][0]["score"] is None


def test_render_json_includes_rankings() -> None:
    summaries = [
        _summary("low.example", score=_score(40)),
        _summary("high.example", score=_score(90)),
    ]
    payload = json.loads(overview_module._render_overview_json("ds", summaries))
    cleanest = payload["rankings"]["cleanest"]
    assert cleanest[0]["slug"] == "high.example"
    assert cleanest[0]["rank"] == 1
    assert payload["rankings"]["worst"][0]["slug"] == "low.example"


def test_render_json_aggregates_common_findings() -> None:
    summaries = [
        _summary("a.example", headlines=[("high", "Leaks email")]),
        _summary("b.example", headlines=[("high", "Leaks email")]),
    ]
    payload = json.loads(overview_module._render_overview_json("ds", summaries))
    assert {
        "severity": "high", "headline": "Leaks email", "sites": 2, "pct": 100.0,
    } in payload["common_findings"]


def test_render_json_serializes_government_reach() -> None:
    summaries = [
        _summary("a.example", gov={"european": {"ec.europa.eu"}}),
        _summary("b.example", gov={"european": {"ec.europa.eu"}}),
    ]
    payload = json.loads(overview_module._render_overview_json("ds", summaries))
    eu = next(
        g for g in payload["government_third_parties"] if g["level"] == "european"
    )
    assert eu["sites"] == 2
    assert {"host": "ec.europa.eu", "sites": 2} in eu["hosts"]


def test_render_json_serializes_paragov_reach() -> None:
    summaries = [_summary("a.example", paragov={"Vendor X": {"cdn.example"}})]
    payload = json.loads(overview_module._render_overview_json("ds", summaries))
    pg = payload["paragov_third_parties"]
    assert pg and pg[0]["vendor"] == "Vendor X"
    assert {"host": "cdn.example", "sites": 1} in pg[0]["hosts"]
