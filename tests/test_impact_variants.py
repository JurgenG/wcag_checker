"""Tests for per-capture variant ratings (Scoring-v2 Phase 5).

A module declares a base triple but may select a *variant* from its own
hits when the capture shows a configuration that changes the impact —
gated on wire-observable evidence only (certainty rule). Two rules from
the proposal (decision 5):

* unobservable settings fall back to the base triple, and
* an evasion-marked variant can only rate *higher* than base.

GA4 is the first variant product: Consent-Mode-denied beacons
(``gcs=G100`` on every collection hit) are a milder privacy reality
than free-running GA4; a cloaked/proxied GA4 hit is a worse one.
"""

from __future__ import annotations

import pytest

from leak_inspector import modules  # noqa: F401  (registers detectors)
from leak_inspector.analysis.runner import analyze_bundle
from leak_inspector.impact import ImpactRating
from leak_inspector.modules.base import (
    CAT_BEHAVIORAL, CAT_CONSENT, CAT_HTTP_TRAFFIC, CAT_IDENTIFIER,
    CAT_PII, IMPACT_LOW, Hit, ParamInfo, all_modules,
)
from tests.fixtures.bundles import path as bundle_path


@pytest.fixture
def ga4():
    return next(m for m in all_modules() if m.module_id == "ga4")


def _p(key: str, value: str, category: str = CAT_BEHAVIORAL) -> ParamInfo:
    return ParamInfo(key=key, value=value, category=category, meaning="",
                     privacy_impact=IMPACT_LOW, event_index=1)


def _ga4_hit(*params: ParamInfo, url: str = "https://region1.google-analytics.com/g/collect") -> Hit:
    return Hit(
        module_id="ga4", module_name="Google Analytics 4", url=url,
        host="region1.google-analytics.com", method="POST",
        response_status=204, started_at="t", params=list(params), events=[1],
    )


# --- the base-class hook -----------------------------------------------------


def test_base_class_hook_returns_the_base_triple() -> None:
    """Any module without a variant override returns its base rating from
    effective_rating(), for any hits."""
    facebook = next(m for m in all_modules() if m.module_id == "facebook_pixel")
    assert facebook.effective_rating([]) == facebook.impact_rating


# --- GA4 consent-denied variant ----------------------------------------------


def test_ga4_base_when_no_consent_signal(ga4) -> None:
    """No observable gcs → base (certainty rule: unobservable settings
    don't exist for scoring)."""
    hit = _ga4_hit(_p("cid", "123.456", CAT_IDENTIFIER))
    assert ga4.effective_rating([hit]) == ga4.impact_rating
    assert ga4.effective_rating([hit]).privacy == 3.0


def test_ga4_consent_denied_lowers_privacy(ga4) -> None:
    """Every collection beacon reports gcs=G100 (storage denied) → no
    durable client-id persisted → milder privacy than free-running."""
    hits = [_ga4_hit(_p("gcs", "G100", CAT_CONSENT)) for _ in range(3)]
    rating = ga4.effective_rating(hits)
    assert rating.privacy < ga4.impact_rating.privacy
    assert rating.privacy == 1.5
    # The snippet and the measurement-layer dependency are unchanged.
    assert rating.security == ga4.impact_rating.security
    assert rating.resilience == ga4.impact_rating.resilience


def test_ga4_mixed_consent_stays_base(ga4) -> None:
    """If any beacon reports granted (G111), it is not a denied-only
    capture → base."""
    hits = [_ga4_hit(_p("gcs", "G100", CAT_CONSENT)),
            _ga4_hit(_p("gcs", "G111", CAT_CONSENT))]
    assert ga4.effective_rating(hits) == ga4.impact_rating


def test_ga4_loader_hits_without_gcs_do_not_block_the_variant(ga4) -> None:
    """The gtag/td loader hits carry no gcs; only beacons that DO report
    consent state are considered (all-denied still fires)."""
    hits = [
        _ga4_hit(url="https://www.googletagmanager.com/gtag/js?id=G-X"),
        _ga4_hit(_p("gcs", "G100", CAT_CONSENT)),
        _ga4_hit(_p("gcs", "G100", CAT_CONSENT)),
    ]
    assert ga4.effective_rating(hits).privacy == 1.5


# --- GA4 evasion override (can only rate higher) -----------------------------


def test_ga4_evasion_marker_raises_above_base(ga4) -> None:
    """A cloaked/proxied GA4 hit → the evasion override; privacy can only
    go up, never down."""
    hit = _ga4_hit(_p("(fp-proxy) host", "g.example.be", CAT_HTTP_TRAFFIC),
                   _p("cid", "1", CAT_IDENTIFIER))
    rating = ga4.effective_rating([hit])
    assert rating.privacy == 4.5
    assert rating.privacy > ga4.impact_rating.privacy


def test_ga4_evasion_overrides_consent_denied(ga4) -> None:
    """Even with gcs=G100, an evasion marker wins — cloaking is the
    worse fact, and the override only ever raises."""
    hit = _ga4_hit(_p("gcs", "G100", CAT_CONSENT),
                   _p("(cname-cloak) canonical", "x", CAT_HTTP_TRAFFIC))
    assert ga4.effective_rating([hit]).privacy == 4.5


# --- GA4 identity-stitching variants (can only rate higher) ------------------


def test_ga4_enhanced_conversions_em_raises_to_5(ga4) -> None:
    """A hashed login email (``em``, Enhanced Conversions / Advanced
    Matching) ships an identified-person key to Google — the gravest
    privacy reality (rubric 5.0)."""
    hit = _ga4_hit(_p("em", "abc123hash", CAT_PII),
                   _p("cid", "1", CAT_IDENTIFIER))
    rating = ga4.effective_rating([hit])
    assert rating.privacy == 5.0
    assert rating.privacy > ga4.impact_rating.privacy
    # Snippet + measurement-layer dependency unchanged — only privacy moves.
    assert rating.security == ga4.impact_rating.security
    assert rating.resilience == ga4.impact_rating.resilience


def test_ga4_enhanced_conversions_ecid_raises_to_5(ga4) -> None:
    """The encrypted-client-id companion field (``ecid``) is part of the
    same Enhanced Conversions matching surface → 5.0."""
    hit = _ga4_hit(_p("ecid", "enc", CAT_IDENTIFIER))
    assert ga4.effective_rating([hit]).privacy == 5.0


def test_ga4_enhanced_conversions_in_post_body_raises_to_5(ga4) -> None:
    """Enhanced Conversions data usually rides in the batched POST body,
    where ``parse()`` relabels keys as ``(body ev#N) em``. The variant
    must match the underlying key, not the display label."""
    hit = _ga4_hit(_p("(body ev#2) em", "abc123hash", CAT_PII))
    assert ga4.effective_rating([hit]).privacy == 5.0


def test_ga4_user_id_join_raises_to_3_5(ga4) -> None:
    """A site-supplied ``uid`` (real account id) stitches the GA4
    pseudonym to a known account → profile joined to a platform identity
    (rubric 3.5)."""
    hit = _ga4_hit(_p("uid", "account-4711", CAT_PII),
                   _p("cid", "1", CAT_IDENTIFIER))
    rating = ga4.effective_rating([hit])
    assert rating.privacy == 3.5
    assert rating.security == ga4.impact_rating.security
    assert rating.resilience == ga4.impact_rating.resilience


# --- precedence ladder: EC-matching > evasion > user-id > consent-denied -----


def test_ga4_em_overrides_evasion(ga4) -> None:
    """Shipping the email is graver than cloaking the tracker — 5.0 wins
    over the 4.5 evasion override."""
    hit = _ga4_hit(_p("em", "h", CAT_PII),
                   _p("(cname-cloak) canonical", "x", CAT_HTTP_TRAFFIC))
    assert ga4.effective_rating([hit]).privacy == 5.0


def test_ga4_em_overrides_consent_denied(ga4) -> None:
    """If ``em`` is observed on the wire it shipped, regardless of a
    ``gcs=G100`` on the same batch — the identified-person fact dominates."""
    hit = _ga4_hit(_p("em", "h", CAT_PII), _p("gcs", "G100", CAT_CONSENT))
    assert ga4.effective_rating([hit]).privacy == 5.0


def test_ga4_uid_overrides_consent_denied(ga4) -> None:
    """A real account join is a certain escalation; it outranks the
    consent-denied de-escalation."""
    hit = _ga4_hit(_p("uid", "account-4711", CAT_PII),
                   _p("gcs", "G100", CAT_CONSENT))
    assert ga4.effective_rating([hit]).privacy == 3.5


def test_ga4_evasion_overrides_uid(ga4) -> None:
    """Cloaking (4.5) is graver than a user-id join (3.5)."""
    hit = _ga4_hit(_p("uid", "account-4711", CAT_PII),
                   _p("(fp-proxy) host", "g.example.be", CAT_HTTP_TRAFFIC))
    assert ga4.effective_rating([hit]).privacy == 4.5


# --- variant selection keys only on GA4's own transmitted params -------------


def test_ga4_set_cookie_named_uid_does_not_trigger_user_id_variant(ga4) -> None:
    """The analysis layer appends response Set-Cookie params as
    ``(set-cookie) <name>``. A cookie that happens to be named ``uid`` is
    not the GA4 User-ID field and must not select the user-id variant."""
    hit = _ga4_hit(_p("cid", "1", CAT_IDENTIFIER),
                   _p("(set-cookie) uid", "abc", CAT_IDENTIFIER))
    assert ga4.effective_rating([hit]) == ga4.impact_rating


def test_ga4_set_cookie_named_em_does_not_trigger_ec_variant(ga4) -> None:
    """Likewise a response cookie named ``em`` is not Enhanced-Conversions
    matching data."""
    hit = _ga4_hit(_p("cid", "1", CAT_IDENTIFIER),
                   _p("(set-cookie) em", "x", CAT_IDENTIFIER))
    assert ga4.effective_rating([hit]) == ga4.impact_rating


def test_ga4_ambient_traffic_param_does_not_trigger_variant(ga4) -> None:
    """Ambient HTTP params (``(http) …``) are connection metadata, never
    GA4 transmitted fields."""
    hit = _ga4_hit(_p("cid", "1", CAT_IDENTIFIER),
                   _p("(http) uid", "x", CAT_HTTP_TRAFFIC))
    assert ga4.effective_rating([hit]) == ga4.impact_rating


# --- real fixture ------------------------------------------------------------


def test_doccle_reject_ga4_selects_consent_denied_variant() -> None:
    """doccle-reject's GA4 beacons all report gcs=G100 — the consent
    pass confirms G100-only — so GA4 scores the milder variant there."""
    analysis = analyze_bundle(bundle_path("doccle-reject.zip"))
    ga4_module = next(m for m in all_modules() if m.module_id == "ga4")
    ga4_hits = [h for h in analysis.hits if h.module_id == "ga4"]
    rating = ga4_module.effective_rating(ga4_hits)
    assert rating.privacy == 1.5


# --- aggregation uses the effective rating -----------------------------------


def test_module_deductions_uses_effective_rating(ga4) -> None:
    """The engine must deduct the variant, not the base, when one fires."""
    from leak_inspector.report.score_v2 import module_deductions

    hits = [_ga4_hit(_p("gcs", "G100", CAT_CONSENT)) for _ in range(2)]
    deductions, unrated = module_deductions(hits, {"ga4": ga4})
    assert len(deductions) == 1
    assert deductions[0].rating.privacy == 1.5
    assert unrated == []
