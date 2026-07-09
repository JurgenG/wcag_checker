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

"""X (Twitter) Ads conversion-tracking pixel detector.

X (formerly Twitter) operates an advertiser-facing conversion-
tracking pixel at the dedicated ``analytics.twitter.com`` host — the
``/i/adsct`` endpoint records pageviews, custom events, and
ecommerce values for advertisers running campaigns on the platform.

Distinct from:

* ``t.co`` — URL-shortener for tweet links (not claimed here).
* ``platform.twitter.com`` / ``platform.x.com`` — embed widgets
  (not claimed here).

This module scopes to ``analytics.twitter.com`` to avoid shadowing
either of the above.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
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


_HOST_EXACT = "analytics.twitter.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "p_id":           (CAT_TECHNICAL, "X Ads partner / advertiser ID",                 IMPACT_LOW),
    "p_user_id":      (CAT_PII,        "Advertiser-supplied user ID (commonly a hashed email or account ID)", IMPACT_HIGH),
    "txn_id":         (CAT_IDENTIFIER, "Transaction / event correlation ID",            IMPACT_MEDIUM),
    "event_id":       (CAT_IDENTIFIER, "Event-instance ID",                              IMPACT_MEDIUM),
    "events":         (CAT_BEHAVIORAL, "Event list (JSON-encoded event spec)",          IMPACT_MEDIUM),
    "tw_sale_amount": (CAT_BEHAVIORAL, "Ecommerce sale amount",                          IMPACT_MEDIUM),
    "tw_order_quantity": (CAT_BEHAVIORAL, "Ecommerce order quantity",                    IMPACT_MEDIUM),
    "tw_document_href": (CAT_CONTENT, "Page URL (where the pixel fired)",                IMPACT_MEDIUM),
    "tw_iframe_status": (CAT_TECHNICAL, "Iframe-context status flag",                    IMPACT_LOW),
    "gdpr":         (CAT_CONSENT, "GDPR-applies flag (0/1)",                              IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "IAB TCF consent string",                               IMPACT_LOW),
    "tpx_cb":       (CAT_TECHNICAL, "Cache-buster",                                        IMPACT_LOW),
}


@register
class XAdsModule(TrackerModule):
    """Detect X (Twitter) Ads conversion-tracking pixel traffic."""

    module_id = "x_ads"
    module_name = "X (Twitter) Ads"
    vendor = "X Corp."
    legal_jurisdiction = "US"
    data_residency = "US (San Francisco, CA / Bastrop, TX); global serving infrastructure"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Social conversion pixel (X/Twitter): privacy 4.0 (cross-site, joins
    #   the visit to the X account graph — cross-site by design). security
    #   2.5 (ordinary pixel). resilience 3.0 (US social-ad platform
    #   dependence — rubric 3.0, the social-pixel shape like Meta/LinkedIn).
    impact_rating = ImpactRating(privacy=4.0, security=2.5, resilience=3.0)
    impact_notes = {
        "privacy": "The X (Twitter) conversion pixel joins this visit to "
            "the X account graph — cross-site by design.",
        "security": "Loads an unpinned X pixel into your origin.",
        "resilience": "A US social-ad platform the outreach depends on.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return event.host.lower() == _HOST_EXACT

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized X Ads parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key, value=value, category=category, meaning=meaning,
                    privacy_impact=impact, event_index=event.event_id,
                )
            )
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
