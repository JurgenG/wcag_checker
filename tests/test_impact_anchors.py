"""Calibration anchors: the curated rating expectations, pinned.

Seeded from ``docs/SCORING.md``'s worked examples and grown
with every Phase-3 family pass. Pinning keeps the sweep honest: if a
later pass would move an already-rated module, the rubric (or the
anchor) must be revisited consciously, in review — not drift.

Each test skips while its module is still unrated and activates
automatically the moment the module gets its triple.

Conscious anchor changes from the proposal's worked-examples table
(the table was illustrative; where it conflicts with the per-domain
rubric, the rubric wins, decided in review):

* 3a: ``google_fonts`` security 0.5 → 1.0 — it serves *CSS*, and
  external stylesheets are rubric security 1.0 (style-capable), not
  0.5 (static binaries). The proposal's ninth worked example (GA4
  behind FP-Mode, 4.5/2.5/3.0) is realized as the
  ``google_first_party_mode`` module's base rating.
* 3b: ``hotjar`` resilience 2.5 → 1.5 — Hotjar is EU-owned
  (Contentsquare SAS, France). The resilience axis is
  jurisdiction-driven, so an EU session-replay vendor must score
  *better* on resilience than the US ones (Clarity/FullStory 2.5);
  the worked example had misfiled it on the high-risk-jurisdiction
  line. Privacy/security (4.5/3.5) unchanged.
"""

from __future__ import annotations

import pytest

from leak_inspector import modules  # noqa: F401  (registers detectors)
from leak_inspector.impact import ImpactRating
from leak_inspector.modules.base import all_modules

#: module_id -> (privacy, security, resilience).
_ANCHORS: dict[str, tuple[float, float, float]] = {
    # proposal worked examples
    "matomo": (2.0, 0.0, 0.0),            # invasive yet fully sovereign
    "ga4": (3.0, 2.5, 3.0),               # self-interested controller
    "facebook_pixel": (4.0, 2.5, 3.5),    # cross-site by design
    "hotjar": (4.5, 3.5, 1.5),            # replay ingests PII; EU vendor
    "adobe_marketing_cloud": (4.0, 4.0, 3.0),  # ID-sync hub
    "icordis": (0.5, 0.5, 0.5),           # operator's own EU supplier
    "polyfill_fastly": (1.0, 4.5, 2.0),   # little data, failed governance
    # 3a — Google family
    "google_fonts": (1.0, 1.0, 2.0),      # presence leak; serves CSS; habit
    "googletagmanager": (1.5, 3.0, 2.5),  # loader: little data, much code
    "google_ads": (4.0, 2.5, 3.5),        # DoubleClick: cross-site by design
    "google_misc": (1.0, 2.0, 2.0),       # catch-all residual, lower bound
    "gstatic": (1.0, 2.0, 2.0),           # chrome + widget JS residual
    "google_cdn": (1.0, 2.5, 2.0),        # bucket/AMP-hosted executables
    "google_maps": (1.5, 2.0, 2.5),       # lookup content, session-tied
    "recaptcha": (3.0, 2.0, 2.5),         # deliberate fingerprinting
    "google_first_party_mode": (4.5, 2.5, 3.0),  # evasion overrides
    # 3b — session replay + social/ads majors
    "clarity": (4.5, 3.5, 2.5),           # session replay, US
    "fullstory": (4.5, 3.5, 2.5),         # session replay, US
    "contentsquare": (4.5, 3.5, 1.5),     # session replay, EU
    "linkedin_insight": (4.0, 2.5, 3.0),  # cross-site, member graph
    "bing_uet": (4.0, 2.5, 3.0),          # cross-site ad pixel
    "criteo": (4.0, 4.0, 1.5),            # SSP/sync hub, EU vendor
    "outbrain": (4.0, 2.5, 2.5),          # content-rec + Amplify pixel
    # 3c — ad-exchange / ID long tail
    "appnexus": (4.0, 4.0, 2.5),          # SSP, US
    "pubmatic": (4.0, 4.0, 2.5),          # SSP, US
    "openx": (4.0, 4.0, 2.5),             # SSP, US
    "index_exchange": (4.0, 4.0, 1.5),    # SSP, CA adequacy
    "magnite": (4.0, 4.0, 2.5),           # SSP, US
    "adform": (4.0, 4.0, 1.5),            # SSP, EU (DK)
    "mediago": (4.0, 4.0, 2.5),           # SSP, CN high-risk
    "lotame": (4.0, 4.0, 2.5),            # DMP, US
    "quantcast": (4.0, 4.0, 2.5),         # DMP+measure+CMP, US
    "id5": (4.0, 3.0, 1.5),               # universal ID, UK adequacy
    "liveramp": (5.0, 3.0, 2.5),          # RampID person-level identity
    "integral_ad_science": (3.0, 2.5, 2.5),  # ad verification, not audience
    "ezoic": (4.0, 4.0, 3.0),             # publisher monetization stack
    # adobe_marketing_cloud (the ID-sync-hub anchor) is in the
    # worked-examples block above — rated in this 3c pass.
    # 3d — EU / self-hosted / public sector
    "plausible": (1.5, 0.0, 0.0),         # cookieless self-hosted analytics
    "snowplow": (2.0, 0.0, 0.0),          # self-hosted event pipeline
    "oswald": (2.5, 1.5, 1.0),            # EU chat widget
    "mailjet": (5.0, 2.5, 1.0),           # email PII out, EU vendor
    "mailchimp": (5.0, 2.5, 3.0),         # email PII out, US vendor
    "hubspot": (5.0, 2.5, 3.0),           # form harvest + US CRM
    "gov_flanders": (1.0, 1.0, 0.5),      # EU public-sector dependency
    "paragov_publiq": (1.0, 1.0, 0.5),    # EU para-public dependency
    # 3e — CDNs / utility / CMPs
    "polyfill_fastly": (1.0, 4.5, 2.0),   # little data, failed governance
    "youtube": (4.0, 1.5, 3.0),           # embed sets DoubleClick cookies
    "cookiebot": (1.5, 2.5, 1.0),         # EU third-party CMP
    "onetrust": (1.5, 3.0, 2.5),          # US CMP, vendor-script loader
    "lcp_icordis_consent": (0.5, 0.0, 0.0),    # self-hosted consent
    "eu_cookie_compliance": (0.5, 0.0, 0.0),   # self-hosted consent
    "openstreetmap": (1.5, 1.0, 1.5),     # the open maps alternative
    # 3f — CNAME-cloak vendors + ad-tech / foreign-analytics long tail
    "eulerian": (4.5, 2.5, 1.5),          # cloak, EU vendor
    "oracle_eloqua": (4.5, 2.5, 3.0),     # cloak, US marketing-automation
    "taboola": (4.0, 2.5, 1.5),           # content-rec, IL adequacy
    "tiktok": (4.0, 2.5, 2.5),            # ByteDance pixel, CN
    "trade_desk": (4.0, 4.0, 2.5),        # DSP + UID2
    "x_ads": (4.0, 2.5, 3.0),             # social conversion pixel
    "baidu_tongji": (3.0, 2.5, 3.0),      # CN analytics
    "yandex_metrica": (3.0, 2.5, 3.0),    # RU analytics (WebVisor variant)
}


@pytest.mark.parametrize("module_id", sorted(_ANCHORS))
def test_anchor_rating(module_id: str) -> None:
    module = next(
        (m for m in all_modules() if m.module_id == module_id), None,
    )
    assert module is not None, f"anchor module {module_id} not registered"
    if module.impact_rating is None:
        pytest.skip(f"{module_id} not yet rated (Phase 3 sweep)")
    privacy, security, resilience = _ANCHORS[module_id]
    assert module.impact_rating == ImpactRating(
        privacy=privacy, security=security, resilience=resilience,
    )
