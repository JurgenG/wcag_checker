# leak_inspector — record what data a website leaks during a real
# human-driven browsing session.
# Copyright (C) 2026 Jurgen Gaeremyn
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""TikTok Pixel / ByteDance web tracker detector.

What a browser capture actually sees from TikTok:

* **Loader** — ``analytics.tiktok.com/i18n/pixel/events.js`` (legacy)
  and ``analytics.tiktok.com/i18n/pixel/sdk.js`` (newer).
* **Beacon** — ``analytics.tiktok.com/api/v2/pixel/track/`` (current)
  and the legacy ``/api/track/`` form. Carries the pixel event payload
  as form-encoded query params plus, often, a JSON body containing
  ``properties`` (event-specific: currency, value, content_id, …)
  and ``context`` (page URL/title/referrer, user pseudo-IDs, library
  metadata). These two JSON blobs are surfaced raw — the per-property
  PII risk depends entirely on operator configuration, so descending
  into the JSON would either under- or over-claim.
* **Ads platform** — ``ads.tiktok.com`` (conversion beacons, GDPR
  consent dialogs), ``business-api.tiktok.com`` (Events API — server-
  side primarily, occasionally also loaded from a browser).

Mobile SDK endpoints (``*.tiktokv.com``, ``log.byteoversea.com``,
``api2-*.tiktokv.com``) are deliberately NOT claimed: they're native
iOS / Android SDK traffic and won't appear in a Firefox capture. They
can be added if a future WebView-driven capture pipeline lands.

Sovereignty: TikTok's nominal EU controller is TikTok Technology
Limited (Ireland), but the Irish DPC's 2023 €345M enforcement
established that personal data is processed by group entities including
those in China. The audit reflects the ultimate controller —
ByteDance Ltd. — so the report flags this as a non-EU flow under
PIPL / Data Security Law, not as an Irish-bound EU flow.

The parameter dictionary is the documented Web Pixel surface only.
Unknown keys fall through to ``CAT_OTHER`` so they're still recorded.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_PII,
    CAT_TECHNICAL,
    Hit,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


#: Primary web pixel host. Both the JS loader and the ``/api/...``
#: beacon endpoints live here.
_ANALYTICS_HOST = "analytics.tiktok.com"

#: Ads-platform host. Most relevant when a site embeds the TikTok
#: conversion script or a CMP triggers an ads cookie sync.
_ADS_HOST = "ads.tiktok.com"

#: Events API host — the server-to-server transport. Occasionally
#: loaded from a browser when the integration includes a client-side
#: fallback. Claiming it lets the module surface those loads too.
_BUSINESS_API_HOST = "business-api.tiktok.com"

_TIKTOK_HOSTS_EXACT: frozenset[str] = frozenset({
    _ANALYTICS_HOST,
    _ADS_HOST,
    _BUSINESS_API_HOST,
})

#: Documented TikTok Pixel parameter dictionary. Web Pixel surface only.
_PARAMS: dict[str, tuple[str, str, str]] = {
    # --- identity ---
    "pixel_code":   (CAT_TECHNICAL,  "TikTok Pixel ID (the advertiser's tracking key)", IMPACT_LOW),
    "ttclid":       (CAT_IDENTIFIER, "TikTok Click ID — cross-device attribution token", IMPACT_HIGH),
    "_ttp":         (CAT_IDENTIFIER, "Persistent visitor pseudonym (the ``_ttp`` first-party cookie)", IMPACT_HIGH),
    "anonymous_id": (CAT_IDENTIFIER, "Pixel-assigned visitor anonymous ID", IMPACT_HIGH),
    "external_id":  (CAT_PII,        "Operator-supplied user ID (often a real account id)", IMPACT_HIGH),
    # --- hashed PII (Advanced Matching) ---
    "email":        (CAT_PII,        "Hashed email (Advanced Matching)",  IMPACT_HIGH),
    "phone_number": (CAT_PII,        "Hashed phone number (Advanced Matching)", IMPACT_HIGH),
    # --- event payload ---
    "event":         (CAT_BEHAVIORAL, "Event name (PageView / ViewContent / AddToCart / InitiateCheckout / CompletePayment / …)", IMPACT_MEDIUM),
    "event_id":      (CAT_TECHNICAL,  "Per-hit ID for server-side de-duplication", IMPACT_LOW),
    "properties":    (CAT_BEHAVIORAL, "Event-specific payload — JSON blob (currency, value, content_id, content_type, sku, …)", IMPACT_MEDIUM),
    "context":       (CAT_CONTENT,    "Page + library context — JSON blob (url, title, referrer, locale, user agent, library version)", IMPACT_MEDIUM),
    "currency":      (CAT_BEHAVIORAL, "Transaction / conversion currency", IMPACT_LOW),
    "value":         (CAT_BEHAVIORAL, "Transaction / conversion monetary value", IMPACT_MEDIUM),
    # --- technical / library plumbing ---
    "partner_name":  (CAT_TECHNICAL,  "Integration partner name (Shopify / WooCommerce / …)", IMPACT_LOW),
    "library":       (CAT_TECHNICAL,  "Pixel library identifier", IMPACT_LOW),
    "library_name":  (CAT_TECHNICAL,  "Pixel library identifier", IMPACT_LOW),
    "library_version": (CAT_TECHNICAL, "Pixel library version", IMPACT_LOW),
    "sdkid":         (CAT_TECHNICAL,  "Pixel SDK version identifier", IMPACT_LOW),
    "timestamp":     (CAT_TECHNICAL,  "Hit client timestamp", IMPACT_LOW),
    # --- consent ---
    "consent":       (CAT_TECHNICAL,  "Consent state forwarded to the pixel", IMPACT_LOW),
}


@register
class TikTokModule(TrackerModule):
    """Detect TikTok Web Pixel beacons on the documented host set."""

    module_id = "tiktok"
    module_name = "TikTok Pixel"
    vendor = "ByteDance Ltd."
    legal_jurisdiction = "CN"
    data_residency = (
        "Nominal EU controller: TikTok Technology Limited (Ireland). "
        "Processing by group entities including ByteDance Ltd. (China) — "
        "Irish DPC enforcement 2023 (€345M) established cross-jurisdiction "
        "access patterns."
    )
    sovereignty_notes = (
        "PIPL and Data Security Law apply via the ultimate parent in China. "
        "Schrems II analysis must consider PRC government access regardless "
        "of the Irish controller-of-record designation; not a US CLOUD Act "
        "exposure but a parallel non-EU access regime."
    )
    # TikTok Pixel (ByteDance): privacy 4.0 (cross-site conversion/audience
    #   tracking joined to the TikTok graph; advanced-matching with hashed
    #   email would be a Phase-5 variant → 5.0). security 2.5 (ordinary
    #   pixel/loader). resilience 2.5 (CN ultimate parent — high-risk
    #   jurisdiction, replaceable ad channel; rubric 2.5).
    impact_rating = ImpactRating(privacy=4.0, security=2.5, resilience=2.5)
    impact_notes = {
        "privacy": "The TikTok Pixel joins this visit to ByteDance's "
            "audience graph for conversion tracking — cross-site by "
            "design.",
        "security": "Loads an unpinned TikTok pixel into your origin.",
        "resilience": "A China-controlled ad dependency — high-risk "
            "jurisdiction, replaceable channel.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return event.host.lower() in _TIKTOK_HOSTS_EXACT

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized TikTok Pixel parameter", IMPACT_LOW)
            )
            params.append(ParamInfo(
                key=key,
                value=value,
                category=category,
                meaning=meaning,
                privacy_impact=impact,
                event_index=event.event_id,
            ))
        return Hit(
            module_id=self.module_id,
            module_name=self.module_name,
            url=event.url,
            host=event.host,
            method=event.method,
            response_status=event.response_status,
            started_at=event.timestamp,
            params=params,
            events=[event.event_id],
        )