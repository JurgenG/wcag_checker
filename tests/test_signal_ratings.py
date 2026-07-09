"""Tests for the non-module signal ratings (Scoring-v2 Phase 4).

Everything that costs points outside the tracker-module registry — the
missing-hardening checks, cookie/consent signals, US-ownership,
end-of-life platform, missing SRI, absent security.txt — carries its
own `(privacy, security, resilience)` triple on the same 33-criteria
rubric (proposal decision 2). This file pins the catalog and that the
triples reach the aggregation engine; the *application* semantics
(cap-vs-deduction, dedup) are Phase-6 calibration, not asserted here.
"""

from __future__ import annotations

import pytest

from leak_inspector import signals
from leak_inspector.impact import ImpactRating, signal_ratings
from leak_inspector.report.score_v2 import Deduction, compute_score_v2


@pytest.fixture(autouse=True)
def _registered():
    """Idempotent: ensure the catalog is in the global registry."""
    signals.register_all()


# --- the catalog is well-formed ----------------------------------------------


def test_catalog_is_non_empty() -> None:
    assert len(signals.SIGNAL_CATALOG) >= 15


def test_every_entry_has_a_valid_triple() -> None:
    for sid, entry in signals.SIGNAL_CATALOG.items():
        assert isinstance(entry.rating, ImpactRating), sid
        assert entry.label, sid
        assert entry.note, sid  # a rubric justification, like the modules


def test_signal_ids_match_their_keys() -> None:
    for sid, entry in signals.SIGNAL_CATALOG.items():
        assert entry.signal_id == sid


def test_the_known_signals_are_present() -> None:
    """The signals the v1 scorer already acts on must all appear."""
    expected = {
        # 11 security posture checks (as their "missing/failing" form)
        "https_broken", "no_https_redirect", "hsts_missing", "csp_missing",
        "xcto_missing", "xfo_missing", "referrer_policy_missing",
        "permissions_policy_missing", "dnssec_unsigned", "dmarc_weak",
        "cookie_hygiene_bad",
        # security extras
        "eol_platform", "missing_sri_script", "missing_sri_stylesheet",
        "security_txt_missing",
        # resilience: server sovereignty (per component × physical/jurisdiction)
        "host_physical_extra_eu", "host_jurisdiction_extra_eu",
        "mail_physical_extra_eu", "mail_jurisdiction_extra_eu",
        "dns_physical_extra_eu", "dns_jurisdiction_extra_eu",
        "no_ipv6",
        # privacy (consent + cookies)
        "persistent_xs_cookie", "forwarded_tracking_cookie",
        "pre_consent_tracking", "post_reject_tracking",
    }
    assert expected <= set(signals.SIGNAL_CATALOG)


# --- each signal lands on the domain it is about -----------------------------


def test_sovereignty_signals_are_resilience_only() -> None:
    for sid in ("host_physical_extra_eu", "host_jurisdiction_extra_eu",
                "mail_physical_extra_eu", "mail_jurisdiction_extra_eu",
                "dns_physical_extra_eu", "dns_jurisdiction_extra_eu"):
        r = signals.SIGNAL_CATALOG[sid].rating
        assert (r.privacy, r.security) == (0.0, 0.0)
        assert r.resilience > 0


def test_jurisdiction_outweighs_physical_location() -> None:
    """The legal-jurisdiction axis costs more than the physical-location axis."""
    for comp in ("host", "mail", "dns"):
        phys = signals.SIGNAL_CATALOG[f"{comp}_physical_extra_eu"].rating
        juris = signals.SIGNAL_CATALOG[f"{comp}_jurisdiction_extra_eu"].rating
        assert juris.resilience > phys.resilience
        assert (phys.resilience, juris.resilience) == (2.0, 3.0)


def test_no_ipv6_is_a_small_resilience_signal() -> None:
    """Absent IPv6 is a minor infrastructure-modernity gap, resilience-only."""
    r = signals.SIGNAL_CATALOG["no_ipv6"].rating
    assert r.resilience > 0
    assert r.resilience <= 0.5
    assert (r.privacy, r.security) == (0.0, 0.0)


def test_security_header_signals_are_security_axis() -> None:
    for sid in ("hsts_missing", "csp_missing", "xcto_missing", "xfo_missing",
                "permissions_policy_missing"):
        r = signals.SIGNAL_CATALOG[sid].rating
        assert r.security > 0
        assert r.resilience == 0.0


def test_referrer_policy_is_dual_axis_security_and_privacy() -> None:
    """A missing Referrer-Policy leaks the full URL to third parties
    (privacy) and weakens framing context (security)."""
    r = signals.SIGNAL_CATALOG["referrer_policy_missing"].rating
    assert r.privacy > 0 and r.security > 0


def test_consent_signals_are_privacy_axis() -> None:
    for sid in ("pre_consent_tracking", "post_reject_tracking",
                "persistent_xs_cookie"):
        r = signals.SIGNAL_CATALOG[sid].rating
        assert r.privacy > 0
        assert (r.security, r.resilience) == (0.0, 0.0)


def test_post_reject_outweighs_pre_consent() -> None:
    """Tracking after an explicit reject is the starker violation."""
    post = signals.SIGNAL_CATALOG["post_reject_tracking"].rating.privacy
    pre = signals.SIGNAL_CATALOG["pre_consent_tracking"].rating.privacy
    assert post > pre


def test_eol_platform_is_a_heavy_security_signal() -> None:
    r = signals.SIGNAL_CATALOG["eol_platform"].rating
    assert r.security >= 4.0


def test_tls_signals_are_present_with_expected_axes() -> None:
    """The three TLS-quality signals carry the calibrated triples:
    an invalid cert is a meaningful security cost (below https_broken,
    above the minor-header gaps); a deprecated protocol is a security
    gap; a near-expiry cert is a minor resilience (outage) concern."""
    invalid = signals.SIGNAL_CATALOG["tls_cert_invalid"].rating
    assert (invalid.privacy, invalid.resilience) == (0.0, 0.0)
    assert invalid.security == 2.0
    assert invalid.security < signals.SIGNAL_CATALOG["https_broken"].rating.security

    legacy = signals.SIGNAL_CATALOG["tls_legacy_protocol"].rating
    assert (legacy.privacy, legacy.resilience) == (0.0, 0.0)
    assert legacy.security == 1.0

    expiring = signals.SIGNAL_CATALOG["tls_cert_expiring_soon"].rating
    assert (expiring.privacy, expiring.security) == (0.0, 0.0)
    assert 0.0 < expiring.resilience <= 0.5


# --- registration + reaching the aggregation engine --------------------------


def test_register_all_populates_the_registry() -> None:
    registry = signal_ratings()
    for sid in signals.SIGNAL_CATALOG:
        assert registry.get(sid) == signals.SIGNAL_CATALOG[sid].rating


def test_register_all_is_idempotent() -> None:
    signals.register_all()
    signals.register_all()  # must not raise on already-registered
    assert "host_jurisdiction_extra_eu" in signal_ratings()


def test_signal_triple_reaches_aggregation() -> None:
    """A signal built into a Deduction deducts on its domain."""
    entry = signals.SIGNAL_CATALOG["host_jurisdiction_extra_eu"]
    score = compute_score_v2([
        Deduction(source_id=entry.signal_id, label=entry.label,
                  kind="signal", rating=entry.rating),
    ])
    assert score.resilience.stars == 10.0 - entry.rating.resilience
    assert score.privacy.stars == 10.0
    assert score.security.stars == 10.0


def test_no_signal_fired_means_no_deduction() -> None:
    assert compute_score_v2([]).security.stars == 10.0


# --- the generated overview now includes signals -----------------------------


def test_every_over_threshold_signal_has_an_explainer() -> None:
    """Completeness gate (signals): every signal whose rating exceeds 1.0
    on a domain must declare a report-facing explainer for that domain."""
    from leak_inspector.report.score_v2 import EXPLAINER_THRESHOLD

    missing = []
    for sid, entry in signals.SIGNAL_CATALOG.items():
        for dom in ("privacy", "security", "resilience"):
            if getattr(entry.rating, dom) > EXPLAINER_THRESHOLD \
                    and dom not in entry.explainers:
                missing.append(f"{sid}.{dom}")
    assert missing == [], f"signals missing explainers: {missing}"


def test_signals_appear_in_the_overview() -> None:
    from leak_inspector import modules  # noqa: F401
    from leak_inspector.impact import ratings_overview_rows
    from leak_inspector.modules.base import all_modules

    rows = ratings_overview_rows(all_modules(), signal_ratings())
    signal_ids = {r["id"] for r in rows if r["kind"] == "signal"}
    assert "eol_platform" in signal_ids
    assert "mail_jurisdiction_extra_eu" in signal_ids
