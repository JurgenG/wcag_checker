"""Tests for the per-capture consent state (Phase 2 of consent-state
detection).

All expectations are pinned against real fixture bundles:

* ``doccle-reject`` / ``doccle-accept`` — Cookiebot, explicit decision.
* ``cultuurkuur`` — Cookie Script; the cookie exists as
  ``{"bannershown":1}`` *before* the visitor decides, so the decision
  moment is the first *decodable* artifact, not the first sighting.
* ``nbb`` — Cookiebot banner loads but the visitor never decides:
  provably state "none" (Cookiebot persists nothing until a choice).
* ``kbc`` — TrustArc, whose decision artifact we can't decode yet:
  honestly "unknown", never guessed.
* ``brecht`` / ``aalst`` — no CMP module fires at all: "unknown".
"""

from __future__ import annotations

import pytest

from leak_inspector import modules  # noqa: F401  (registers detectors)
from leak_inspector.analysis.consent import ConsentState
from leak_inspector.analysis.runner import analyze_events
from leak_inspector.bundle.reader import BundleReader

from tests.fixtures.bundles import path as bundle_path


def _analyze(name: str):
    with BundleReader(bundle_path(name)) as b:
        return analyze_events(
            b.manifest, b.events(), cname_chains=b.cname_chains,
        )


@pytest.fixture(scope="module")
def consent_by_bundle():
    return {
        name: _analyze(f"{name}.zip").consent
        for name in (
            "doccle-reject", "doccle-accept", "cultuurkuur",
            "nbb", "kbc", "brecht", "aalst",
        )
    }


def test_rejected_session(consent_by_bundle) -> None:
    c = consent_by_bundle["doccle-reject"]
    assert isinstance(c, ConsentState)
    assert c.state == "rejected"
    assert c.source == "cookiebot"
    assert c.granted == ()
    assert c.decided_at == "2026-05-30T15:46:30.254771Z"


def test_accepted_session(consent_by_bundle) -> None:
    c = consent_by_bundle["doccle-accept"]
    assert c.state == "accepted"
    assert c.source == "cookiebot"
    assert c.granted == ("marketing", "preferences", "statistics")
    assert c.decided_at == "2026-05-30T15:39:28.790006Z"


def test_decision_moment_is_first_decodable_artifact(consent_by_bundle) -> None:
    """cultuurkuur's CookieScriptConsent exists as bannershown-only
    from 22:12:43; the first decodable reject lands at 22:13:31."""
    c = consent_by_bundle["cultuurkuur"]
    assert c.state == "rejected"
    assert c.source == "cookie_script"
    assert c.decided_at == "2026-05-28T22:13:31.494946Z"


def test_no_interaction_with_decodable_cmp(consent_by_bundle) -> None:
    """nbb loads Cookiebot but the visitor never decides — provably
    state 'none', because Cookiebot persists nothing until a choice."""
    c = consent_by_bundle["nbb"]
    assert c.state == "none"
    assert c.source is None
    assert c.decided_at is None


def test_undecodable_cmp_is_unknown(consent_by_bundle) -> None:
    """kbc runs TrustArc; without a decodable artifact the state is
    'unknown' — never inferred from banner presence alone."""
    assert consent_by_bundle["kbc"].state == "unknown"


@pytest.mark.parametrize("name", ["brecht", "aalst"])
def test_no_cmp_is_unknown(consent_by_bundle, name) -> None:
    assert consent_by_bundle[name].state == "unknown"


def test_unknown_with_cmp_names_the_banner(consent_by_bundle) -> None:
    """kbc's TrustArc banner is detected even though its decision can't
    be decoded — the state carries the CMP name so reports can say
    'banner present, decision unreadable' instead of nothing."""
    assert consent_by_bundle["kbc"].cmp_names == ("TrustArc (formerly TRUSTe)",)


@pytest.mark.parametrize("name", ["brecht", "aalst"])
def test_unknown_without_cmp_has_no_names(consent_by_bundle, name) -> None:
    assert consent_by_bundle[name].cmp_names == ()


def test_decodable_states_carry_cmp_name_too(consent_by_bundle) -> None:
    assert consent_by_bundle["doccle-reject"].cmp_names == ("Cookiebot",)
