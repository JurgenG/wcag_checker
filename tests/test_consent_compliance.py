"""Tests for consent-compliance offenders (Phase 3 of consent-state
detection).

A tracking hit offends when it ships a PII/identifier field to a
third party. The CMP modules are exempt — they must run before the
decision to draw the banner and record the choice.

* **pre-decision** vendors fired before the visitor decided (a
  violation regardless of the eventual choice — consent wasn't given
  yet). For state ``none`` (banner shown, never decided) every
  tracking vendor is pre-consent by construction.
* **post-reject** vendors fired *after* an explicit reject — the
  starkest violation: the visitor said no and tracking continued.
* ``unknown`` sessions make no claim (we can't read the decision).

All sets pinned against real fixture bundles.
"""

from __future__ import annotations

import pytest

from leak_inspector import modules  # noqa: F401  (registers detectors)
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
            "doccle-reject", "doccle-accept", "cultuurkuur", "nbb", "kbc",
        )
    }


def test_reject_session_pre_and_post_offenders(consent_by_bundle) -> None:
    c = consent_by_bundle["doccle-reject"]
    assert c.pre_decision_vendors == (
        "Google Ads / DoubleClick", "Google Analytics 4", "Oswald.ai",
    )
    # Tracking continued after the visitor rejected — the worst case.
    assert c.post_reject_vendors == (
        "Google Ads / DoubleClick", "Google Analytics 4", "Matomo",
        "Microsoft Clarity", "Oswald.ai",
    )


def test_accept_session_makes_no_violation_claim(consent_by_bundle) -> None:
    """Accepted: the visitor consented, and the snapshot boundary can't
    cleanly separate pre-accept from post-accept beacons (they burst at
    the click — Matomo here fires 0.13s after the true accept but
    before the lagging snapshot). So we assert no pre-consent
    violation rather than risk a false accusation."""
    c = consent_by_bundle["doccle-accept"]
    assert c.state == "accepted"
    assert c.pre_decision_vendors == ()
    assert c.post_reject_vendors == ()


def test_cultuurkuur_reject_offenders(consent_by_bundle) -> None:
    c = consent_by_bundle["cultuurkuur"]
    assert c.pre_decision_vendors == ("Google Analytics 4",)
    assert c.post_reject_vendors == ("Google Analytics 4",)


def test_no_interaction_all_tracking_is_pre_consent(consent_by_bundle) -> None:
    """nbb: banner shown, never decided → any tracking vendor counts as
    pre-consent. (Here there are none, which is why nbb scores well.)"""
    c = consent_by_bundle["nbb"]
    assert c.state == "none"
    assert c.pre_decision_vendors == ()
    assert c.post_reject_vendors == ()


def test_unknown_makes_no_compliance_claim(consent_by_bundle) -> None:
    """kbc runs TrustArc (undecodable) — we can't say whether its
    Adobe hit was consented, so it is neither pre nor post."""
    c = consent_by_bundle["kbc"]
    assert c.state == "unknown"
    assert c.pre_decision_vendors == ()
    assert c.post_reject_vendors == ()


def test_consent_mode_signals_corroborate_on_the_wire(
    consent_by_bundle,
) -> None:
    """Google Consent Mode ``gcs`` reports the state each beacon fired
    under: G100 = denied, G111 = granted. doccle-reject only ever
    reports denied; doccle-accept reports both (before/after accept)."""
    assert consent_by_bundle["doccle-reject"].consent_mode_signals == ("G100",)
    assert consent_by_bundle["doccle-accept"].consent_mode_signals == (
        "G100", "G111",
    )
    assert consent_by_bundle["cultuurkuur"].consent_mode_signals == ()
