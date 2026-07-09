"""Tests for the scoring columns + score-ordered ranking in the bulk overview.

Each row in the all-reports table now leads with the composite score
columns ``TOT  RES  SEC  PRIV`` (in that visual order), and rows are
sorted by total descending (best at the top).

Sites whose ReportDocument has ``score is None`` (the hermetic
``analyze_events`` path produces this — no posture, no score) get
em-dashes in the score columns and sort after every scored row.

Failed captures (no analysis at all) keep their existing behaviour:
empty score, sorted to the bottom alongside the unscored rows.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BULK_DIR = Path(__file__).resolve().parent.parent / "bulk-tool"
if str(_BULK_DIR) not in sys.path:
    sys.path.insert(0, str(_BULK_DIR))

import overview as overview_module  # noqa: E402

from leak_inspector.report.score_v2 import DimensionView, ScoreView


def _dim(stars: int) -> DimensionView:
    # Inputs are the old 0-10 scale; v2 dimensions are 0-100, so ×10.
    return DimensionView(stars=stars * 10, max_stars=100, rationale="x",
                         penalty=0.0, deductions=())


def _breakdown(res: int, sec: int, priv: int) -> ScoreView:
    # Cube-root total of the 0-100 dimensions (matches the real model);
    # with inputs ×10 the totals match the old geometric-mean numbers
    # (e.g. (8,8,10) → ³√(80·80·100) = 86).
    total = round((res * 10 * sec * 10 * priv * 10) ** (1 / 3))
    return ScoreView(
        resilience=_dim(res),
        security=_dim(sec),
        privacy=_dim(priv),
        total=total, max_total=100, top_action=None,
    )


def _summary(
    slug: str,
    *,
    score: ScoreBreakdown | None,
    is_failed: bool = False,
):
    """Build a minimal SiteSummary with just the fields the ranking touches."""
    from overview import SiteSummary
    from leak_inspector.report.document import CaptureStatus

    return SiteSummary(
        slug=slug,
        target_url=f"https://{slug}/",
        landing_url=f"https://{slug}/",
        report_filename=f"{slug}.report.html" if not is_failed else "",
        high_finding_count=0,
        medium_finding_count=0,
        low_finding_count=0,
        total_high_impact_fields=0,
        trackers_fired=0,
        third_party_hosts_touched=0,
        finding_headlines=[],
        capture_status=(
            CaptureStatus(http_status=None, reason="failed", is_failure=True)
            if is_failed else None
        ),
        score=score,
    )


# --- SiteSummary carries the score breakdown -----------------------------


def test_site_summary_has_score_field() -> None:
    """SiteSummary gained a ``score: ScoreBreakdown | None`` field."""
    s = _summary("a.example", score=_breakdown(8, 8, 10))
    assert s.score is not None
    assert s.score.total == 86


def test_site_summary_score_can_be_none() -> None:
    """Hermetic / no-posture analyses → score is None."""
    s = _summary("a.example", score=None)
    assert s.score is None


# --- _render_full_list sorts by total descending --------------------------


def test_full_list_orders_by_total_descending() -> None:
    rows = [
        _summary("low.example",  score=_breakdown(4, 4, 4)),     # ~40
        _summary("mid.example",  score=_breakdown(6, 6, 6)),     # 60
        _summary("high.example", score=_breakdown(10, 10, 10)),  # 100
    ]
    html = overview_module._render_full_list(rows)
    # Best at the top → "high" before "mid" before "low".
    high_pos = html.index("high.example")
    mid_pos = html.index("mid.example")
    low_pos = html.index("low.example")
    assert high_pos < mid_pos < low_pos


def test_full_list_places_unscored_sites_at_the_bottom() -> None:
    """Sites without a score (None) sort after every scored site."""
    rows = [
        _summary("nope.example", score=None),
        _summary("ok.example", score=_breakdown(6, 6, 6)),
    ]
    html = overview_module._render_full_list(rows)
    ok_pos = html.index("ok.example")
    nope_pos = html.index("nope.example")
    assert ok_pos < nope_pos


def test_full_list_places_failed_captures_at_the_bottom() -> None:
    """Failed captures (no analysis) join the unscored block at the bottom."""
    rows = [
        _summary("fail.example", score=None, is_failed=True),
        _summary("ok.example", score=_breakdown(8, 8, 8)),
    ]
    html = overview_module._render_full_list(rows)
    assert html.index("ok.example") < html.index("fail.example")


# --- The four columns appear (TOT / RES / SEC / PRIV) -------------------


def test_full_list_renders_four_score_columns_in_header() -> None:
    rows = [_summary("a.example", score=_breakdown(8, 8, 10))]
    html = overview_module._render_full_list(rows)
    # Header strings (column titles). Match exactly to pin the order.
    assert "<th>TOT</th>" in html
    assert "<th>🛡️ RES</th>" in html
    assert "<th>🔐 SEC</th>" in html
    assert "<th>🕶️ PRIV</th>" in html
    # The four score columns precede the Site column.
    site_pos = html.index("<th>Site</th>")
    for col in ("<th>TOT</th>", "<th>🛡️ RES</th>",
                "<th>🔐 SEC</th>", "<th>🕶️ PRIV</th>"):
        assert html.index(col) < site_pos


def test_full_list_renders_score_values_in_cells() -> None:
    rows = [_summary("a.example", score=_breakdown(8, 8, 10))]
    html = overview_module._render_full_list(rows)
    # The total + each dimension value must appear in the row.
    # ³√(80 × 80 × 100) ≈ 85.5 → 86.
    assert "86" in html
    # The dimensions show their 0-100 values (inputs ×10).
    assert ">80<" in html   # resilience + security cells
    assert ">100<" in html  # privacy cell


def test_full_list_renders_emdash_for_unscored_rows() -> None:
    """Unscored rows show em-dashes in the four score columns, not '0/10'."""
    rows = [_summary("nope.example", score=None)]
    html = overview_module._render_full_list(rows)
    # Don't accidentally render "0" — the row simply has no score.
    # The cell content for an unscored dimension is an em-dash.
    assert "—" in html
