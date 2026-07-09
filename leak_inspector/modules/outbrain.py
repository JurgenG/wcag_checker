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

"""Outbrain tracking pixel + Amplify detector.

Outbrain runs a content-recommendation network plus an "Amplify" pixel
that advertisers embed to attribute downstream conversions back to
Outbrain-driven traffic. Both ride on the ``outbrain.com`` domain
family.

Recognized hosts:

* ``tr.outbrain.com`` — tracking endpoints (``/unifiedPixel``,
  ``/cachedClickId``, conversion + pageview).
* ``amplify.outbrain.com`` — Amplify pixel loader (``/cp/obtp.js``).
* ``wave.outbrain.com`` — alternate ingest seen via GTM-managed installs.
* ``widgets.outbrain.com`` — content-recommendation widget assets.
* ``log.outbrain.com`` — internal-event log endpoint.
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
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIX = ".outbrain.com"
_HOST_EXACT = "outbrain.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "marketerId":   (CAT_TECHNICAL, "Outbrain marketer / advertiser ID (per-customer)", IMPACT_LOW),
    "obApiKey":     (CAT_TECHNICAL, "Outbrain Amplify API key (per-customer)", IMPACT_LOW),
    "widgetJSId":   (CAT_TECHNICAL, "Widget instance ID",                       IMPACT_LOW),
    "widgetId":     (CAT_TECHNICAL, "Widget instance ID (alt form)",            IMPACT_LOW),
    "id":           (CAT_TECHNICAL, "Generic identifier (widget / pixel context)", IMPACT_LOW),
    "ctp":          (CAT_IDENTIFIER, "Click-through pixel correlation token",   IMPACT_MEDIUM),
    "name":         (CAT_BEHAVIORAL, "Event name (PAGE_VIEW, custom conversion, …)", IMPACT_MEDIUM),
    "event":        (CAT_BEHAVIORAL, "Event identifier (alt form)",             IMPACT_MEDIUM),
    "src":          (CAT_BEHAVIORAL, "Event source (alt form)",                 IMPACT_LOW),
    "category":     (CAT_BEHAVIORAL, "Event category",                          IMPACT_LOW),
    "permalink":    (CAT_CONTENT, "Page canonical URL",                         IMPACT_MEDIUM),
    "referrer":     (CAT_CONTENT, "Document referrer",                          IMPACT_MEDIUM),
    "pRef":         (CAT_CONTENT, "Previous referrer in history",               IMPACT_MEDIUM),
    "dl":           (CAT_CONTENT, "Document location (page URL)",               IMPACT_MEDIUM),
    "url":          (CAT_CONTENT, "Page URL (alt form)",                        IMPACT_MEDIUM),
    "title":        (CAT_CONTENT, "Page title",                                 IMPACT_LOW),
    "cht":          (CAT_TECHNICAL, "Client hint type (e.g. ``gtm`` = loaded via GTM)", IMPACT_LOW),
    "obApiVersion": (CAT_TECHNICAL, "Amplify API version",                      IMPACT_LOW),
    "zone":         (CAT_TECHNICAL, "Server region zone",                       IMPACT_LOW),
    "pld":          (CAT_TECHNICAL, "Payload sequence number",                  IMPACT_LOW),
    "g":            (CAT_TECHNICAL, "Internal numeric flag (semantics not documented)", IMPACT_LOW),
    "au":           (CAT_TECHNICAL, "Auto-update flag",                         IMPACT_LOW),
    "idx":          (CAT_BEHAVIORAL, "Item index within a widget",              IMPACT_LOW),
    "bust":         (CAT_TECHNICAL, "Random cache-buster",                      IMPACT_LOW),
    "rn":           (CAT_TECHNICAL, "Random cache-buster (alt form)",           IMPACT_LOW),
    "v":            (CAT_TECHNICAL, "Pixel protocol version",                   IMPACT_LOW),
    "gdpr":         (CAT_CONSENT, "GDPR-applies flag",                          IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "TCF consent string",                         IMPACT_LOW),
}


@register
class OutbrainModule(TrackerModule):
    """Detect Outbrain Amplify pixel and content-recommendation widget traffic."""

    module_id = "outbrain"
    module_name = "Outbrain"
    vendor = "Outbrain Inc."
    legal_jurisdiction = "US"
    data_residency = "US headquarters; global serving infrastructure with regional zones"
    sovereignty_notes = "US CLOUD Act applies"
    # privacy 4.0: content-recommendation + Amplify attribution pixel with
    #   cross-site cookie sync — joins the visit to an ad/content profile
    #   (rubric privacy 4.0). security 2.5: this module fingerprints the
    #   tracking/Amplify pixels (tr.outbrain.com), an ordinary pixel
    #   surface — not Criteo's OpenRTB sync hub. resilience 2.5: US
    #   vendor, replaceable supporting content/outreach channel (rubric
    #   2.5).
    impact_rating = ImpactRating(privacy=4.0, security=2.5, resilience=2.5)
    impact_notes = {
        "privacy": "Content-recommendation + Amplify attribution with "
            "cross-site cookie sync — joins the visit to an ad/content "
            "profile.",
        "security": "Loads an unpinned Outbrain pixel into your origin.",
        "resilience": "A US content/outreach vendor — replaceable "
            "supporting feature.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Outbrain parameter", IMPACT_LOW)
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
