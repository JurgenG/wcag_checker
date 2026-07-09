"""Tests for the Scoring-v2 aggregation engine (roadmap Phase 2).

The model decided in ``docs/SCORING.md``: every fired module
and signal deducts its per-domain impact from a starting 10;
dimensions floor at zero; the geometric-mean composite is unchanged;
the existing hard caps stay ceilings on top of the deduction result.
All synthetic — the engine is pure and lives alongside the old math
(nothing rewires ``compute_score`` until Phase 6).
"""

from __future__ import annotations

import pytest

from leak_inspector.impact import ImpactRating
from leak_inspector.report.score_v2 import (
    Deduction,
    compute_score_v2,
    module_deductions,
)


def _d(source_id: str, p: float, s: float, r: float,
       *, kind: str = "module") -> Deduction:
    return Deduction(
        source_id=source_id, label=source_id, kind=kind,
        rating=ImpactRating(privacy=p, security=s, resilience=r),
    )


# --- the cumulative model ------------------------------------------------------


def test_empty_capture_scores_perfect() -> None:
    score = compute_score_v2([])
    assert score.privacy.stars == 10.0
    assert score.security.stars == 10.0
    assert score.resilience.stars == 10.0
    assert score.total == 100


def test_one_deduction_subtracts_per_domain() -> None:
    score = compute_score_v2([_d("ga4", 3.0, 2.5, 3.0)])
    assert score.privacy.stars == 7.0
    assert score.security.stars == 7.5
    assert score.resilience.stars == 7.0


def test_deductions_cumulate_across_modules_and_signals() -> None:
    score = compute_score_v2([
        _d("ga4", 3.0, 2.5, 3.0),
        _d("facebook_pixel", 4.0, 2.5, 3.5),
        _d("us_owned_mail", 0.0, 0.0, 0.5, kind="signal"),
    ])
    assert score.privacy.stars == 3.0       # 10 − 3 − 4
    assert score.security.stars == 5.0      # 10 − 2.5 − 2.5
    assert score.resilience.stars == 3.0    # 10 − 3 − 3.5 − 0.5


def test_many_small_ones_zero_a_dimension() -> None:
    """Twenty 0.5-impact embeds → a really bad site (the decision)."""
    score = compute_score_v2([
        _d(f"embed{i}", 0.5, 0.0, 0.0) for i in range(20)
    ])
    assert score.privacy.stars == 0.0
    assert score.total == 0


def test_floor_never_goes_sub_zero() -> None:
    score = compute_score_v2([
        _d("a", 5.0, 5.0, 5.0), _d("b", 5.0, 5.0, 5.0),
        _d("c", 5.0, 5.0, 5.0),
    ])
    assert score.privacy.stars == 0.0
    assert score.security.stars == 0.0
    assert score.resilience.stars == 0.0


# --- composite (unchanged geometric mean) --------------------------------------


def test_composite_matches_documented_examples() -> None:
    # (6, 6, 6) → 60 and (10, 4, 6) → 62, per docs/SCORING.md.
    score = compute_score_v2([_d("x", 4.0, 4.0, 4.0)])
    assert (score.privacy.stars, score.security.stars,
            score.resilience.stars) == (6.0, 6.0, 6.0)
    assert score.total == 60
    # (10, 4, 6) is not constructible from one triple (max impact 5)
    # — stack two signals for security −6 / resilience −4.
    score = compute_score_v2([
        _d("s1", 0.0, 5.0, 0.0, kind="signal"),
        _d("s2", 0.0, 1.0, 4.0, kind="signal"),
    ])
    assert (score.privacy.stars, score.security.stars,
            score.resilience.stars) == (10.0, 4.0, 6.0)
    assert score.total == 62


def test_zero_dimension_zeroes_the_total() -> None:
    score = compute_score_v2([
        _d("replay", 5.0, 3.5, 2.5), _d("adnet", 5.0, 4.0, 3.0),
    ])
    assert score.privacy.stars == 0.0
    assert score.total == 0


# --- caps stay ceilings ----------------------------------------------------------


def test_cap_lowers_but_never_lifts() -> None:
    # Deductions land privacy at 8 → cap 5 binds.
    capped = compute_score_v2(
        [_d("x", 2.0, 0.0, 0.0)],
        privacy_caps=[(5.0, "capped at 5 (persistent tracking cookie)")],
    )
    assert capped.privacy.stars == 5.0
    assert capped.privacy.cap == (
        5.0, "capped at 5 (persistent tracking cookie)",
    )
    # Deductions land privacy at 3 → the same cap must NOT lift it.
    floored = compute_score_v2(
        [_d("x", 3.5, 0.0, 0.0), _d("y", 3.5, 0.0, 0.0)],
        privacy_caps=[(5.0, "capped at 5 (persistent tracking cookie)")],
    )
    assert floored.privacy.stars == 3.0
    assert floored.privacy.cap is None


def test_tightest_cap_wins() -> None:
    score = compute_score_v2(
        [],
        privacy_caps=[(5.0, "pre-consent"), (2.0, "post-reject")],
    )
    assert score.privacy.stars == 2.0
    assert score.privacy.cap == (2.0, "post-reject")


def test_security_and_resilience_caps_apply_to_their_dimension() -> None:
    score = compute_score_v2(
        [],
        security_caps=[(5.0, "end-of-life platform")],
    )
    assert score.security.stars == 5.0
    assert score.privacy.stars == 10.0


# --- the result carries its own explanation -------------------------------------


def test_dimension_records_its_deductions_largest_first() -> None:
    score = compute_score_v2([
        _d("small", 0.5, 0.0, 0.0),
        _d("big", 4.0, 0.0, 0.0),
        _d("mid", 2.0, 0.0, 0.0),
    ])
    assert [(line.label, line.amount) for line in score.privacy.deductions] \
        == [("big", 4.0), ("mid", 2.0), ("small", 0.5)]


def test_zero_impact_entries_are_not_listed() -> None:
    score = compute_score_v2([_d("css_cdn", 1.0, 0.5, 0.0)])
    assert score.resilience.deductions == ()
    assert score.resilience.stars == 10.0


# --- extracting module deductions from fired hits --------------------------------


class _FakeModule:
    def __init__(self, module_id, name, rating):
        self.module_id = module_id
        self.module_name = name
        self.impact_rating = rating


class _FakeHit:
    def __init__(self, module_id):
        self.module_id = module_id


def _registry(*specs):
    return {
        module_id: _FakeModule(module_id, name, rating)
        for module_id, name, rating in specs
    }


def test_module_deducts_once_regardless_of_hit_count() -> None:
    registry = _registry(
        ("ga4", "Google Analytics 4", ImpactRating(3.0, 2.5, 3.0)),
    )
    hits = [_FakeHit("ga4")] * 17
    deductions, unrated = module_deductions(hits, registry)
    assert len(deductions) == 1
    assert deductions[0].source_id == "ga4"
    assert deductions[0].label == "Google Analytics 4"
    assert deductions[0].kind == "module"
    assert unrated == []


def test_products_of_one_vendor_each_deduct() -> None:
    """Per-product counting: three Google products = three deductions
    (deliberately retires the one-vendor-one-decision collapse)."""
    registry = _registry(
        ("ga4", "Google Analytics 4", ImpactRating(3.0, 2.5, 3.0)),
        ("google_ads", "Google Ads", ImpactRating(3.5, 2.5, 3.5)),
        ("googletagmanager", "Google Tag Manager", ImpactRating(1.5, 3.0, 3.0)),
    )
    hits = [_FakeHit("ga4"), _FakeHit("google_ads"),
            _FakeHit("googletagmanager"), _FakeHit("ga4")]
    deductions, _ = module_deductions(hits, registry)
    assert sorted(d.source_id for d in deductions) == [
        "ga4", "google_ads", "googletagmanager",
    ]


def test_unrated_module_deducts_nothing_but_is_reported() -> None:
    """Transition honesty: an unrated module must not silently score
    as harmless — it contributes nothing and is named."""
    registry = _registry(("newvendor", "New Vendor", None))
    deductions, unrated = module_deductions(
        [_FakeHit("newvendor")], registry,
    )
    assert deductions == []
    assert unrated == ["newvendor"]


def test_unknown_module_id_is_reported_as_unrated() -> None:
    deductions, unrated = module_deductions([_FakeHit("ghost")], {})
    assert deductions == []
    assert unrated == ["ghost"]
