"""Tests for the per-dimension score histograms in the bulk overview.

Alongside the composite-total bar chart, the overview renders one small
histogram per scoring dimension (resilience / security / privacy) so a
reader can see *which* axis drags the dataset down. These tests pin the
binning data per dimension, not the SVG markup.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BULK_DIR = Path(__file__).resolve().parent.parent / "bulk-tool"
if str(_BULK_DIR) not in sys.path:
    sys.path.insert(0, str(_BULK_DIR))

import overview as overview_module  # noqa: E402

from leak_inspector.report.score_v2 import DimensionView, ScoreView


def _score(*, res: int, sec: int, priv: int, total: int = 0) -> ScoreView:
    def dim(stars: int) -> DimensionView:
        return DimensionView(stars=stars, max_stars=100, rationale="x",
                             penalty=0.0, deductions=())
    return ScoreView(
        resilience=dim(res), security=dim(sec), privacy=dim(priv),
        total=total, max_total=100, top_action=None,
    )


def _summary(slug: str, score: ScoreView | None):
    from overview import SiteSummary

    return SiteSummary(
        slug=slug, target_url="", landing_url="",
        report_filename=f"{slug}.report.html",
        high_finding_count=0, medium_finding_count=0, low_finding_count=0,
        total_high_impact_fields=0, trackers_fired=0,
        third_party_hosts_touched=0, finding_headlines=[], score=score,
    )


def test_dimension_histogram_counts_per_dimension() -> None:
    rows = [
        _summary("a", _score(res=10, sec=40, priv=70)),
        _summary("b", _score(res=10, sec=50, priv=70)),
    ]
    res = overview_module._dimension_histogram(rows, "resilience")
    sec = overview_module._dimension_histogram(rows, "security")
    priv = overview_module._dimension_histogram(rows, "privacy")
    assert res[10] == 2                      # both sites at resilience 10
    assert sec[40] == 1 and sec[50] == 1     # security split
    assert priv[70] == 2                     # both at privacy 70


def test_dimension_histogram_excludes_unscored() -> None:
    rows = [
        _summary("a", _score(res=12, sec=0, priv=0)),
        _summary("nope", None),
    ]
    counts = overview_module._dimension_histogram(rows, "resilience")
    assert sum(counts) == 1
    assert counts[12] == 1


def test_dimension_histogram_spans_zero_to_max() -> None:
    rows = [_summary("a", _score(res=3, sec=0, priv=0))]
    counts = overview_module._dimension_histogram(rows, "resilience")
    assert len(counts) == 4          # 0..3
    assert counts[3] == 1


def test_dimension_histogram_empty_with_no_scores() -> None:
    assert overview_module._dimension_histogram([], "security") == []
    assert overview_module._dimension_histogram(
        [_summary("nope", None)], "security"
    ) == []


def test_dimension_section_renders_all_three_dimensions() -> None:
    """The rendered section labels each of the three dimensions."""
    rows = [_summary("a", _score(res=10, sec=20, priv=30, total=19))]
    html = overview_module._render_score_distribution(rows)
    assert "Resilience" in html
    assert "Security" in html
    assert "Privacy" in html
    # Three dimension charts plus the composite-total chart = 4 SVGs.
    assert html.count("<svg") == 4
