"""EU public-sector collaboration is not scored like a commercial tracker.

Leaning on a Belgian/EU public-sector platform (a municipal cooperative
like IMIO, a public vzw like publiq, a regional government platform like
Vlaanderen / Burgerprofiel) is a sovereignty *gain*, not an operational
dependency. So the scoring applies a structural rule, keyed on the
``government`` / ``para_government`` module kinds with an EU-jurisdiction
guardrail:

* resilience impact → 0 (it is the resilient, sovereign choice);
* privacy / security impact → trimmed to a thin floor (a third party
  still sees the visitor / can ship script), not zeroed.

No bonus is applied — the engine stays deduction-only.
"""

from __future__ import annotations

from dataclasses import dataclass

from leak_inspector import modules  # noqa: F401  (registers detectors)
from leak_inspector.analysis.runner import analyze_bundle
from leak_inspector.impact import ImpactRating
from leak_inspector.modules.base import (
    MODULE_KIND_PARA_GOVERNMENT,
    MODULE_KIND_TRACKER,
    all_modules,
)
from leak_inspector.report import score_v2
from tests.fixtures.bundles import path as bundle_path

_MODULES = {m.module_id: m for m in all_modules()}
_PUBLIC_SECTOR_CAP = 0.5


@dataclass
class _StubModule:
    module_kind: str
    legal_jurisdiction: str


def test_eu_government_module_loses_resilience_and_trims_pii_security() -> None:
    """A regional government module (Vlaanderen, jurisdiction BE)."""
    module = _MODULES["gov_flanders"]
    adjusted = score_v2._public_sector_adjusted(module, module.impact_rating)
    assert adjusted.resilience == 0.0
    assert adjusted.privacy <= _PUBLIC_SECTOR_CAP
    assert adjusted.security <= _PUBLIC_SECTOR_CAP


def test_eu_paragov_module_is_adjusted() -> None:
    """A para-governmental cooperative (IMIO, jurisdiction BE)."""
    module = _MODULES["paragov_imio"]
    adjusted = score_v2._public_sector_adjusted(module, module.impact_rating)
    assert adjusted == ImpactRating(privacy=0.5, security=0.5, resilience=0.0)


def test_commercial_tracker_is_unchanged() -> None:
    """A normal commercial tracker keeps its full rating."""
    module = _MODULES["google_ads"]
    rating = module.impact_rating
    assert score_v2._public_sector_adjusted(module, rating) == rating


def test_non_eu_public_sector_is_not_given_leniency() -> None:
    """Guardrail: a public-sector-kind module outside the EU keeps its
    rating (leniency is for EU/EEA public-sector entities only)."""
    stub = _StubModule(
        module_kind=MODULE_KIND_PARA_GOVERNMENT, legal_jurisdiction="US",
    )
    rating = ImpactRating(privacy=1.0, security=1.0, resilience=0.5)
    assert score_v2._public_sector_adjusted(stub, rating) == rating


def test_tracker_kind_is_unchanged_even_if_eu() -> None:
    """The rule keys on kind, not jurisdiction alone: an EU *tracker*
    (not public-sector) is still scored in full."""
    stub = _StubModule(
        module_kind=MODULE_KIND_TRACKER, legal_jurisdiction="BE",
    )
    rating = ImpactRating(privacy=2.0, security=2.0, resilience=2.0)
    assert score_v2._public_sector_adjusted(stub, rating) == rating


def test_public_sector_deduction_is_adjusted_end_to_end() -> None:
    """Through module_deductions: the gov_flanders hit on a real bundle
    deducts 0 resilience and a trimmed privacy/security."""
    analysis = analyze_bundle(bundle_path("aalst.zip"))
    deductions, _ = score_v2.module_deductions(analysis.hits, _MODULES)
    gov = next(d for d in deductions if d.source_id == "gov_flanders")
    assert gov.rating.resilience == 0.0
    assert gov.rating.privacy <= _PUBLIC_SECTOR_CAP
    assert gov.rating.security <= _PUBLIC_SECTOR_CAP
