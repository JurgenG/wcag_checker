"""Tests for the Scoring-v2 rating substrate (roadmap Phase 1).

The `ImpactRating` triple is the unit of the whole overhaul: every
module and every non-module signal carries one — `(privacy, security,
resilience)`, each 0.0–5.0 in half-point steps (the 33-criteria rubric
in ``docs/SCORING.md``). This file pins the contract:
well-formedness is enforced at construction, modules *may* declare a
rating (completeness becomes the Phase-3f gate), signals register
theirs in a shared registry, and the overview table is generated from
the registries — never hand-maintained.
"""

from __future__ import annotations

import pytest

from leak_inspector.impact import (
    ImpactRating,
    ratings_overview_rows,
    register_signal_rating,
    signal_ratings,
)


# --- the triple is validated at construction ---------------------------------


def test_valid_triple_constructs() -> None:
    r = ImpactRating(privacy=3.0, security=2.5, resilience=3.0)
    assert (r.privacy, r.security, r.resilience) == (3.0, 2.5, 3.0)


def test_bounds_are_zero_to_five() -> None:
    ImpactRating(privacy=0.0, security=0.0, resilience=0.0)
    ImpactRating(privacy=5.0, security=5.0, resilience=5.0)
    with pytest.raises(ValueError):
        ImpactRating(privacy=5.5, security=0.0, resilience=0.0)
    with pytest.raises(ValueError):
        ImpactRating(privacy=0.0, security=-0.5, resilience=0.0)


def test_only_half_point_steps_allowed() -> None:
    """11 possible values per domain — 0.3 is not a rating."""
    with pytest.raises(ValueError):
        ImpactRating(privacy=0.3, security=0.0, resilience=0.0)
    with pytest.raises(ValueError):
        ImpactRating(privacy=0.0, security=2.25, resilience=0.0)


def test_integers_are_accepted_as_floats() -> None:
    r = ImpactRating(privacy=4, security=0, resilience=2)
    assert r.privacy == 4.0


def test_rating_is_immutable() -> None:
    r = ImpactRating(privacy=1.0, security=1.0, resilience=1.0)
    with pytest.raises(Exception):
        r.privacy = 2.0  # type: ignore[misc]


# --- modules may declare a rating; a declared one is well-formed -------------


def test_modules_may_declare_a_rating_and_declared_ones_are_valid() -> None:
    """Phase 1 contract: ``TrackerModule.impact_rating`` exists and is
    either ``None`` (not yet rated — the sweep is Phase 3) or a real
    ``ImpactRating``. Completeness is asserted only at the Phase-3f
    gate."""
    from leak_inspector import modules  # noqa: F401  (registers)
    from leak_inspector.modules.base import TrackerModule, all_modules

    assert hasattr(TrackerModule, "impact_rating")
    for module in all_modules():
        rating = module.impact_rating
        assert rating is None or isinstance(rating, ImpactRating), (
            module.module_id
        )


def test_every_registered_module_carries_a_rating() -> None:
    """The Phase-3f completeness gate: the rating sweep is done, so every
    registered tracker module must now declare a well-formed
    ``impact_rating``. A new module added without one fails here — a
    deliberate prompt to rate it against the rubric in
    ``docs/SCORING.md`` rather than let it score as harmless."""
    from leak_inspector import modules  # noqa: F401  (registers detectors)
    from leak_inspector.modules.base import all_modules

    missing = [
        m.module_id for m in all_modules()
        if not isinstance(m.impact_rating, ImpactRating)
    ]
    assert missing == [], f"modules missing an impact_rating: {missing}"


# --- signal-rating registry ---------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_signal_registry(monkeypatch):
    """Each test sees an empty signal registry (the real declarations
    arrive in Phase 4 next to the signal definitions)."""
    from leak_inspector import impact

    monkeypatch.setattr(impact, "_SIGNAL_RATINGS", {})


def test_signal_registration_round_trips() -> None:
    rating = ImpactRating(privacy=0.0, security=0.0, resilience=0.5)
    register_signal_rating("us_owned_mail", rating)
    assert signal_ratings() == {"us_owned_mail": rating}


def test_duplicate_signal_registration_raises() -> None:
    rating = ImpactRating(privacy=0.0, security=1.0, resilience=0.0)
    register_signal_rating("csp_missing", rating)
    with pytest.raises(ValueError):
        register_signal_rating("csp_missing", rating)


def test_signal_ratings_returns_a_copy() -> None:
    register_signal_rating("x", ImpactRating(0.0, 0.0, 0.5))
    snapshot = signal_ratings()
    snapshot["injected"] = ImpactRating(5.0, 5.0, 5.0)
    assert "injected" not in signal_ratings()


# --- generated overview --------------------------------------------------------


class _FakeModule:
    def __init__(self, module_id, module_name, rating):
        self.module_id = module_id
        self.module_name = module_name
        self.impact_rating = rating


def test_overview_rows_cover_modules_and_signals() -> None:
    rated = _FakeModule("ga4", "Google Analytics 4",
                        ImpactRating(3.0, 2.5, 3.0))
    register_signal_rating(
        "security_txt_missing", ImpactRating(0.0, 0.5, 0.0),
    )
    rows = ratings_overview_rows([rated], signal_ratings())
    assert {
        "kind": "module", "id": "ga4", "name": "Google Analytics 4",
        "privacy": 3.0, "security": 2.5, "resilience": 3.0,
    } in rows
    assert {
        "kind": "signal", "id": "security_txt_missing",
        "name": "security_txt_missing",
        "privacy": 0.0, "security": 0.5, "resilience": 0.0,
    } in rows


def test_overview_shows_unrated_modules_as_gaps() -> None:
    """During the Phase-3 sweep the generated table is the worklist:
    unrated modules appear with ``None`` ratings, never silently
    dropped."""
    rows = ratings_overview_rows(
        [_FakeModule("newvendor", "New Vendor", None)], {},
    )
    assert rows == [{
        "kind": "module", "id": "newvendor", "name": "New Vendor",
        "privacy": None, "security": None, "resilience": None,
    }]


def test_overview_rows_are_deterministically_ordered() -> None:
    rows = ratings_overview_rows(
        [
            _FakeModule("zeta", "Z", ImpactRating(1.0, 1.0, 1.0)),
            _FakeModule("alpha", "A", ImpactRating(1.0, 1.0, 1.0)),
        ],
        {"beta_signal": ImpactRating(0.0, 0.0, 0.5)},
    )
    assert [(r["kind"], r["id"]) for r in rows] == [
        ("module", "alpha"), ("module", "zeta"), ("signal", "beta_signal"),
    ]


def test_every_over_threshold_module_domain_has_an_explainer() -> None:
    """Completeness gate (modules): the explainer sweep is done, so every
    domain whose impact exceeds the threshold must carry an
    ``impact_notes`` entry. A new module (or a raised rating) without its
    explainer fails here — the deliberate prompt to write one. Domains at
    or below the threshold are "minor" and stand on the label alone.
    """
    from leak_inspector import modules  # noqa: F401
    from leak_inspector.modules.base import all_modules
    from leak_inspector.report.score_v2 import EXPLAINER_THRESHOLD

    missing = []
    for m in all_modules():
        rating = m.impact_rating
        if rating is None:
            continue
        notes = getattr(m, "impact_notes", {}) or {}
        for dom in ("privacy", "security", "resilience"):
            if getattr(rating, dom) > EXPLAINER_THRESHOLD and dom not in notes:
                missing.append(f"{m.module_id}.{dom}")
    assert missing == [], f"modules missing explainers: {missing}"
