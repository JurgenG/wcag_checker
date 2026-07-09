"""Tests for the score-distribution histogram in the bulk overview.

The overview embeds a bar graph of how many sites landed on each
composite total score (one bar per integer score, x-axis 0 → the
dataset's highest score). These tests pin the **binning data** — the
per-score counts — not the SVG markup that renders them.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BULK_DIR = Path(__file__).resolve().parent.parent / "bulk-tool"
if str(_BULK_DIR) not in sys.path:
    sys.path.insert(0, str(_BULK_DIR))

import overview as overview_module  # noqa: E402

from leak_inspector.report.score_v2 import DimensionView, ScoreView


def _score(total: int) -> ScoreView:
    """A ScoreView whose only field the histogram reads is ``total``."""
    dim = DimensionView(stars=0, max_stars=100, rationale="x",
                         penalty=0.0, deductions=())
    return ScoreView(
        resilience=dim, security=dim, privacy=dim,
        total=total, max_total=100, top_action=None,
    )


def _summary(slug: str, *, total: int | None, is_failed: bool = False):
    from overview import SiteSummary
    from leak_inspector.report.document import CaptureStatus

    return SiteSummary(
        slug=slug,
        target_url=f"https://{slug}/",
        landing_url=f"https://{slug}/",
        report_filename="" if is_failed else f"{slug}.report.html",
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
        score=None if total is None else _score(total),
    )


def test_histogram_counts_sites_per_score() -> None:
    """One count per integer score; index == score value."""
    rows = [
        _summary("a", total=10),
        _summary("b", total=10),
        _summary("c", total=12),
    ]
    counts = overview_module._score_histogram(rows)
    assert counts[10] == 2
    assert counts[12] == 1


def test_histogram_spans_zero_to_max_inclusive() -> None:
    """The list runs 0..max(score) — empty bins in between stay zero."""
    rows = [_summary("a", total=3), _summary("b", total=7)]
    counts = overview_module._score_histogram(rows)
    assert len(counts) == 8          # indices 0..7
    assert counts[0] == 0
    assert counts[3] == 1
    assert counts[5] == 0            # gap bin
    assert counts[7] == 1


def test_histogram_excludes_unscored_sites() -> None:
    """Sites with no score (hermetic / no posture) don't appear."""
    rows = [_summary("a", total=5), _summary("nope", total=None)]
    counts = overview_module._score_histogram(rows)
    assert sum(counts) == 1
    assert counts[5] == 1


def test_histogram_excludes_failed_captures() -> None:
    """Failed captures carry no score and are left out of the distribution."""
    rows = [
        _summary("ok", total=5),
        _summary("fail", total=None, is_failed=True),
    ]
    counts = overview_module._score_histogram(rows)
    assert sum(counts) == 1


def test_histogram_empty_when_no_scored_sites() -> None:
    """No scored sites → empty list (renderer shows nothing)."""
    assert overview_module._score_histogram([]) == []
    assert overview_module._score_histogram(
        [_summary("nope", total=None)]
    ) == []


# --- SVG renderer: data boundary only (no markup/style assertions) --------


def test_histogram_svg_empty_for_no_data() -> None:
    """Nothing to plot → empty string, so the section is skipped."""
    assert overview_module._render_score_histogram_svg([]) == ""


def test_histogram_svg_emits_svg_when_data_present() -> None:
    """With data, the renderer returns an inline <svg> element."""
    svg = overview_module._render_score_histogram_svg([0, 0, 1, 2, 1])
    assert "<svg" in svg
