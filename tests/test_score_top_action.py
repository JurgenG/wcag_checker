"""The "biggest win" is the deduction with the largest TOTAL impact
summed across the three domains — and its displayed cost reflects that
total, not a single domain.
"""

from __future__ import annotations

from leak_inspector.impact import ImpactRating
from leak_inspector.report.score_v2 import Deduction, _top_action


def _ded(label: str, privacy: float, security: float, resilience: float,
         kind: str = "module") -> Deduction:
    return Deduction(
        source_id=label, label=label, kind=kind,
        rating=ImpactRating(privacy=privacy, security=security, resilience=resilience),
    )


def test_module_touching_more_domains_wins_on_total_impact() -> None:
    """A module hitting all three domains (sum 6) beats one with a bigger
    single-domain hit but smaller footprint (sum 5)."""
    broad = _ded("Broad", 2.0, 2.0, 2.0)        # sum 6, three domains
    narrow = _ded("Narrow", 5.0, 0.0, 0.0)      # sum 5, one domain
    action = _top_action([broad, narrow])
    assert "Broad" in action and "Narrow" not in action


def test_multi_domain_cost_shows_the_total_and_breakdown() -> None:
    """The displayed cost is the summed total plus a per-domain breakdown
    (biggest domain first), not a single domain."""
    action = _top_action([_ded("Meta Pixel", 4.0, 2.5, 3.5)])
    assert action == (
        "Remove or replace Meta Pixel "
        "(−10 total: privacy 4, resilience 3.5, security 2.5)"
    )


def test_single_domain_cost_names_that_domain() -> None:
    """A one-domain module reads naturally as '−N domain'."""
    action = _top_action([_ded("Privacy-only", 3.0, 0.0, 0.0)])
    assert action == "Remove or replace Privacy-only (−3 privacy)"


def test_signal_deduction_uses_address_verb() -> None:
    """Non-module deductions (signals) say 'Address' rather than 'Remove'."""
    action = _top_action([_ded("DMARC missing", 0.0, 1.0, 0.0, kind="signal")])
    assert action.startswith("Address: DMARC missing")


def test_no_deductions_has_no_action() -> None:
    assert _top_action([]) is None
