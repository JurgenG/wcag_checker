"""Tests for the logistic dimension model (Scoring-v2 calibration).

Each dimension's summed penalty is mapped through an S-curve so both
100 (perfection) and 0 are asymptotes — the closer to either end, the
less a further penalty moves the score, with the steepest response in
the middle. The three 0–100 dimensions combine by cube root, as the
linear model's total does.
"""

from __future__ import annotations

import math

import pytest

from leak_inspector.impact import ImpactRating
from leak_inspector.report.score_v2 import (
    DEFAULT_P50,
    DEFAULT_S,
    Deduction,
    compute_score_logistic,
    logistic_score,
)


def _d(p: float, s: float, r: float, *, label: str = "x") -> Deduction:
    return Deduction(source_id=label, label=label, kind="module",
                     rating=ImpactRating(privacy=p, security=s, resilience=r))


def _chunks(total: float) -> list[float]:
    """Split a penalty into valid 0–5 half-step impact pieces (a single
    ImpactRating maxes at 5.0, so larger penalties come from stacking)."""
    pieces: list[float] = []
    remaining = round(total * 2) / 2
    while remaining > 5.0:
        pieces.append(5.0)
        remaining -= 5.0
    if remaining > 0:
        pieces.append(remaining)
    return pieces


def _pens(*, privacy: float = 0.0, security: float = 0.0,
          resilience: float = 0.0) -> list[Deduction]:
    """Deductions whose per-domain columns sum to the given penalties."""
    out: list[Deduction] = []
    for i, v in enumerate(_chunks(privacy)):
        out.append(_d(v, 0.0, 0.0, label=f"p{i}"))
    for i, v in enumerate(_chunks(security)):
        out.append(_d(0.0, v, 0.0, label=f"s{i}"))
    for i, v in enumerate(_chunks(resilience)):
        out.append(_d(0.0, 0.0, v, label=f"r{i}"))
    return out


# --- the curve ---------------------------------------------------------------


def test_p50_scores_fifty() -> None:
    assert logistic_score(12.0, p50=12.0, s=6.0) == pytest.approx(50.0)


def test_zero_penalty_is_just_under_100() -> None:
    """Perfection is an asymptote — a penalty-free dimension is high but
    never exactly 100."""
    score = logistic_score(0.0, p50=12.0, s=6.0)
    assert 80.0 < score < 100.0
    assert score == pytest.approx(100.0 / (1.0 + math.exp(-2.0)))


def test_curve_is_monotonic_decreasing() -> None:
    prev = 101.0
    for penalty in range(0, 60):
        cur = logistic_score(float(penalty), p50=12.0, s=6.0)
        assert cur < prev
        prev = cur


def test_curve_stays_within_bounds_including_extremes() -> None:
    for penalty in (0.0, 5.0, 12.0, 50.0, 5000.0):
        score = logistic_score(penalty, p50=12.0, s=6.0)
        assert 0.0 <= score <= 100.0


def test_large_penalty_is_overflow_safe() -> None:
    assert logistic_score(1e9, p50=12.0, s=6.0) == 0.0


def test_marginal_impact_is_smallest_near_the_extremes() -> None:
    """The defining property: one more penalty point moves the score
    most in the middle (near 50) and least near either asymptote."""
    def step(penalty: float) -> float:
        return abs(logistic_score(penalty, p50=12.0, s=6.0)
                   - logistic_score(penalty + 1.0, p50=12.0, s=6.0))

    near_perfect = step(0.0)    # high end
    middle = step(12.0)         # at p50
    near_zero = step(40.0)      # low end
    assert middle > near_perfect
    assert middle > near_zero


def test_steeper_s_sharpens_the_middle() -> None:
    """Smaller s → a sharper transition (bigger swing per point at p50)."""
    sharp = abs(logistic_score(12.0, p50=12.0, s=3.0)
                - logistic_score(13.0, p50=12.0, s=3.0))
    gentle = abs(logistic_score(12.0, p50=12.0, s=9.0)
                 - logistic_score(13.0, p50=12.0, s=9.0))
    assert sharp > gentle


# --- per-dimension application + cube-root total -----------------------------


def test_no_deductions_scores_near_100_on_every_dimension() -> None:
    score = compute_score_logistic([])
    anchor = logistic_score(0.0, p50=DEFAULT_P50, s=DEFAULT_S)
    for dim in (score.privacy, score.security, score.resilience):
        assert dim.penalty == 0.0
        assert dim.score == pytest.approx(anchor)
    assert anchor > 85.0  # a penalty-free dimension reaches ~90 (the ceiling)
    assert score.total == pytest.approx(score.privacy.score)


def test_each_dimension_uses_its_own_penalty() -> None:
    """A privacy-only deduction lowers privacy, leaves S/R untouched."""
    score = compute_score_logistic(_pens(privacy=8.0))
    assert score.privacy.penalty == 8.0
    assert score.security.penalty == 0.0
    assert score.resilience.penalty == 0.0
    assert score.privacy.score < score.security.score


def test_total_is_cube_root_of_the_three_dimensions() -> None:
    score = compute_score_logistic(_pens(privacy=5.0, security=10.0, resilience=2.0))
    expected = (
        score.privacy.score * score.security.score * score.resilience.score
    ) ** (1 / 3)
    assert score.total == pytest.approx(expected)


def test_balanced_dimensions_make_total_equal_the_dimension() -> None:
    score = compute_score_logistic(_pens(privacy=7.0, security=7.0, resilience=7.0))
    assert score.privacy.score == score.security.score == score.resilience.score
    assert score.total == pytest.approx(score.privacy.score)


def test_one_weak_dimension_drags_the_cube_root_total_down() -> None:
    balanced = compute_score_logistic(_pens(privacy=4.0, security=4.0, resilience=4.0)).total
    one_weak = compute_score_logistic(_pens(privacy=30.0, security=4.0, resilience=4.0)).total
    assert one_weak < balanced


def test_penalties_cumulate_within_a_dimension() -> None:
    """Many small deductions add up before the curve is applied."""
    score = compute_score_logistic([_d(1.0, 0.0, 0.0) for _ in range(10)])
    assert score.privacy.penalty == 10.0


def test_heavy_sites_separate_instead_of_clamping_to_zero() -> None:
    """The point of the curve: two badly-tracked sites stay ordered near
    the bottom rather than both pinning to 0."""
    worse = compute_score_logistic(_pens(privacy=34.0)).privacy.score
    bad = compute_score_logistic(_pens(privacy=25.0)).privacy.score
    assert 0.0 < worse < bad
    assert bad < 20.0


def test_view_carries_raw_score_for_the_calculation_section() -> None:
    """DimensionView exposes the un-ceiled raw score, and ceil(raw)
    equals the displayed stars — the data the report's calculation
    section shows so the derivation is exact."""
    from leak_inspector import modules, signals  # noqa: F401
    from leak_inspector.analysis.runner import analyze_bundle
    from leak_inspector.modules.base import all_modules
    from leak_inspector.report.score_v2 import build_score_view
    from tests.fixtures.bundles import path as bundle_path

    analysis = analyze_bundle(bundle_path("aalst.zip"))
    view = build_score_view(analysis, {m.module_id: m for m in all_modules()})
    for dim in (view.privacy, view.security, view.resilience):
        assert 0.0 < dim.raw_score < 100.0
        assert dim.stars == math.ceil(dim.raw_score)


def test_display_ceils_so_zero_and_100_are_never_printed() -> None:
    """The view ceils the raw score: any positive raw ceils to ≥1 (0 is
    never printed) and the penalty-free anchor (~90) ceils to 91 (100 is
    never printed) — both ends asymptotic in the displayed integer."""
    from leak_inspector.report.score_v2 import _display

    assert _display(0.00005) == 1          # catastrophic → 1, not 0
    assert _display(logistic_score(0.0, p50=DEFAULT_P50, s=DEFAULT_S)) == 91
    assert _display(50.0) == 50
    assert _display(64.1) == 65
    assert _display(0.0) == 0              # a true zero stays 0


def test_deductions_listed_largest_first() -> None:
    score = compute_score_logistic([
        _d(0.5, 0.0, 0.0, label="small"),
        _d(4.0, 0.0, 0.0, label="big"),
    ])
    assert [line.label for line in score.privacy.deductions] == ["big", "small"]
