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

"""Taboola content-recommendation + advertising detector.

Taboola runs a content-recommendation / native-advertising network
(``Taboola Newsroom``, ``Taboola Feed``) plus a conversion pixel.
Visitor IDs are minted on first contact and reused across the
publisher network.

Recognized hosts:

* ``*.taboola.com`` (incl. ``trc.taboola.com``, ``cdn.taboola.com``,
  ``vidstat.taboola.com``).

Notable paths:

* ``/sg/<partner>/<version>/cm`` — cookie-match endpoint; the
  publisher partner name is encoded in the path.
* ``/libtrc/<partner>/loader.js`` — Taboola Reach loader script.
* ``/sg/<partner>/<version>/rec`` — recommendation slot fetch.
"""

from __future__ import annotations

import re

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


_HOST_SUFFIX = ".taboola.com"
_HOST_EXACT = "taboola.com"

_PARTNER_PATH_RE = re.compile(r"^/(?:sg|libtrc)/([^/]+)/")


_PARAMS: dict[str, tuple[str, str, str]] = {
    "tabid":   (CAT_IDENTIFIER, "Taboola visitor pseudonym",                IMPACT_MEDIUM),
    "partner": (CAT_TECHNICAL, "Publisher partner ID",                      IMPACT_LOW),
    "pid":     (CAT_TECHNICAL, "Publisher partner ID (alt form)",           IMPACT_LOW),
    "pubid":   (CAT_TECHNICAL, "Publisher ID",                              IMPACT_LOW),
    "event":   (CAT_BEHAVIORAL, "Event name (pageview, conversion, …)",     IMPACT_MEDIUM),
    "name":    (CAT_BEHAVIORAL, "Event name (alt form)",                    IMPACT_MEDIUM),
    "id":      (CAT_BEHAVIORAL, "Event / placement identifier",             IMPACT_LOW),
    "url":     (CAT_CONTENT, "Page URL",                                    IMPACT_MEDIUM),
    "referrer": (CAT_CONTENT, "Document referrer",                          IMPACT_MEDIUM),
    "title":   (CAT_CONTENT, "Page title",                                  IMPACT_LOW),
    "gdpr":         (CAT_CONSENT, "GDPR-applies flag (0/1)",                 IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "IAB TCF consent string",                  IMPACT_LOW),
    "us_privacy":   (CAT_CONSENT, "IAB CCPA US-privacy string",              IMPACT_LOW),
    "v":       (CAT_TECHNICAL, "SDK / pixel version",                        IMPACT_LOW),
}


@register
class TaboolaModule(TrackerModule):
    """Detect Taboola content-recommendation and cookie-sync traffic."""

    module_id = "taboola"
    module_name = "Taboola"
    vendor = "Taboola.com, Ltd."
    legal_jurisdiction = "IL"
    data_residency = "Israel (Tel Aviv HQ); NASDAQ-listed; US operations and CDN"
    sovereignty_notes = (
        "Israeli jurisdiction primary; US CLOUD Act may reach US-operated "
        "infrastructure / NASDAQ-listed corporate structure"
    )
    # Content-recommendation + native-ad pixel (like Outbrain): privacy
    #   4.0 (cross-site cookie sync joins the visit to an ad/content
    #   profile). security 2.5 (ordinary pixel/loader, not an OpenRTB sync
    #   hub). resilience 1.5 (Israel — non-EU *adequacy* country, rubric
    #   1.5).
    impact_rating = ImpactRating(privacy=4.0, security=2.5, resilience=1.5)
    impact_notes = {
        "privacy": "Content-recommendation + native-ad cookie sync — "
            "joins the visit to an ad/content profile.",
        "security": "Loads an unpinned Taboola pixel into your origin.",
        "resilience": "Israel-based — a non-EU adequacy jurisdiction.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []

        from urllib.parse import urlparse
        path = urlparse(event.url).path
        partner_match = _PARTNER_PATH_RE.match(path)
        if partner_match:
            params.append(
                ParamInfo(
                    key="(path) partner",
                    value=partner_match.group(1),
                    category=CAT_TECHNICAL,
                    meaning="Taboola publisher partner ID embedded in the URL path",
                    privacy_impact=IMPACT_LOW,
                    event_index=event.event_id,
                )
            )

        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Taboola parameter", IMPACT_LOW)
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
