"""Top-3 / Worst-3 cards must agree with the full list's ordering.

The cards used to rank by ``ranking_weight`` (a finding-count
heuristic predating the composite score) while the all-reports list
ranks by ``score.total`` — so the cards' ends didn't match the list's
ends. Both now rank by the composite score; the weight survives only
as a tie-breaker (and as the ranking for legacy unscored datasets).
"""

from __future__ import annotations

import sys
from pathlib import Path

_BULK_DIR = Path(__file__).resolve().parent.parent / "bulk-tool"
if str(_BULK_DIR) not in sys.path:
    sys.path.insert(0, str(_BULK_DIR))

from overview import SiteSummary, _render_overview_html, _select_rankings  # noqa: E402

from leak_inspector.report.score_v2 import DimensionView, ScoreView  # noqa: E402


def _breakdown(total: int, raw: float | None = None) -> ScoreView:
    """A ScoreView with the given displayed total and exact ``raw_total``.

    ``raw`` defaults to ``total`` (a consistent view); pass it explicitly
    to model two sites that share a displayed integer but differ in their
    true underlying value.
    """
    dim = DimensionView(stars=total, max_stars=100, rationale="x",
                        penalty=0.0, deductions=())
    return ScoreView(resilience=dim, security=dim, privacy=dim,
                     total=total, max_total=100, top_action=None,
                     raw_total=float(total) if raw is None else raw)


def _site(
    slug: str,
    *,
    total: int | None,
    raw: float | None = None,
    high: int = 0,
) -> SiteSummary:
    return SiteSummary(
        slug=slug, target_url=f"https://{slug}/",
        landing_url=f"https://{slug}/",
        report_filename=f"{slug}.report.html",
        high_finding_count=high,
        medium_finding_count=0, low_finding_count=0,
        total_high_impact_fields=0, trackers_fired=0,
        third_party_hosts_touched=0, finding_headlines=[],
        score=None if total is None else _breakdown(total, raw),
    )


def test_cards_rank_by_composite_score() -> None:
    """Best = highest totals, worst = lowest totals — the same metric
    (and therefore the same ends) as the all-reports list."""
    summaries = [
        _site("mid-a.be", total=60),
        _site("best.be", total=90),
        _site("worst.be", total=10),
        _site("mid-b.be", total=50),
        _site("second-best.be", total=80),
        _site("second-worst.be", total=20),
    ]
    best, worst = _select_rankings(summaries)
    assert [s.slug for s in best[:2]] == ["best.be", "second-best.be"]
    assert [s.slug for s in worst[:2]] == ["worst.be", "second-worst.be"]


def test_card_ends_match_full_list_ends() -> None:
    """The #1 cleanest is the full list's first row; the #1 worst is
    the full list's last scored row."""
    summaries = [
        _site(f"site-{i:02d}.be", total=total)
        for i, total in enumerate([40, 90, 0, 60, 20, 80, 50, 30])
    ]
    html = _render_overview_html("test", summaries)
    best_block = html[html.find("Top 3 cleanest"):html.find("Worst 3")]
    worst_block = html[html.find("Worst 3"):html.find("Most common findings")]
    full_list = html[html.find("All reports"):]

    # Highest total (90) leads the best card; lowest (0) leads worst.
    assert "site-01.be" in best_block      # total 90
    assert "site-02.be" in worst_block     # total 0
    # And the full list's first/last entries are those same sites.
    first_row = full_list.find("site-01.be")
    assert first_row != -1
    assert all(
        full_list.find(f"site-{i:02d}.be") > first_row
        for i in [0, 2, 3, 4, 5, 6, 7]
        if full_list.find(f"site-{i:02d}.be") != -1
    )


def test_cards_break_ties_by_raw_total_not_alphabetically() -> None:
    """Two sites sharing a displayed integer rank by their exact un-ceiled
    value — so the genuinely cleaner site leads even when its slug sorts
    later alphabetically."""
    summaries = [
        _site("zzz-cleaner.be", total=50, raw=49.9),
        _site("aaa-dirtier.be", total=50, raw=49.1),
    ]
    best, worst = _select_rankings(summaries)
    assert best[0].slug == "zzz-cleaner.be"   # 49.9 > 49.1, not alphabetical
    assert worst[0].slug == "aaa-dirtier.be"


def test_full_list_breaks_ties_by_raw_total() -> None:
    """The all-reports table orders same-integer rows by the raw value."""
    from overview import _full_list_order

    rows = [
        _site("aaa-dirtier.be", total=50, raw=49.1),
        _site("zzz-cleaner.be", total=50, raw=49.9),
    ]
    ordered = [s.slug for s in _full_list_order(rows)]
    assert ordered == ["zzz-cleaner.be", "aaa-dirtier.be"]


def test_unscored_sites_stay_out_of_the_cards() -> None:
    """A hermetic/unscored site can't be meaningfully ranked — it must
    not occupy a Top/Worst slot (it still shows in the all-reports
    list, at the bottom)."""
    summaries = [
        _site("scored-a.be", total=80),
        _site("scored-b.be", total=40),
        _site("unscored.be", total=None, high=99),
    ]
    best, worst = _select_rankings(summaries)
    slugs = {s.slug for s in best} | {s.slug for s in worst}
    assert "unscored.be" not in slugs


def test_all_unscored_dataset_falls_back_to_weight() -> None:
    """Legacy datasets without scores still get meaningful cards,
    ranked by the finding-count weight."""
    summaries = [
        _site("clean.be", total=None, high=0),
        _site("dirty.be", total=None, high=9),
        _site("middle.be", total=None, high=2),
    ]
    best, worst = _select_rankings(summaries)
    assert best[0].slug == "clean.be"
    assert worst[0].slug == "dirty.be"
