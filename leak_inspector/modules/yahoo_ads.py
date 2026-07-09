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

"""Yahoo Ads / Yahoo DSP detector.

Yahoo's advertising platform (a successor to Yahoo Right Media + Yahoo
Gemini + Verizon Media DSP, after Apollo Global Management's 2021
acquisition of Yahoo from Verizon) participates in the open-RTB
cookie-sync chain. Pixel calls observed on publisher pages typically
sync a partner-supplied user ID into Yahoo's audience graph.

Recognized hosts:

* ``*.analytics.yahoo.com`` — cookie-sync + measurement endpoints
  (``ups.analytics.yahoo.com``, ``cms.analytics.yahoo.com``).
* ``*.ads.yahoo.com`` — additional ad-serving paths.

Notable endpoint:

* ``/ups/<advertiser-id>/cms`` — user-profile-sync cookie-match
  handler; advertiser is in the path, partner identity in the query
  string.
"""

from __future__ import annotations

import re

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_CONSENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_HIGH,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIXES = (".analytics.yahoo.com", ".ads.yahoo.com")
_HOST_EXACTS = {"analytics.yahoo.com", "ads.yahoo.com"}

_UPS_PATH_RE = re.compile(r"^/ups/(\d+)/")


_PARAMS: dict[str, tuple[str, str, str]] = {
    "partner_id":  (CAT_TECHNICAL,  "Partner / data source initiating the sync (e.g. ``ADOBE`` = AAM)", IMPACT_LOW),
    "_hosted_id":  (CAT_IDENTIFIER, "Partner-supplied user ID being synced into Yahoo's audience graph", IMPACT_HIGH),
    "uid":         (CAT_IDENTIFIER, "Partner-supplied user ID (alt form)",                              IMPACT_HIGH),
    "advertiser_id": (CAT_TECHNICAL,  "Yahoo advertiser ID",                                            IMPACT_LOW),
    "_ev":         (CAT_TECHNICAL, "Event / variant flag",                                              IMPACT_LOW),
    "redir":       (CAT_TECHNICAL, "Redirect target after sync completes",                              IMPACT_LOW),
    "r":           (CAT_TECHNICAL, "Redirect target (alt form)",                                        IMPACT_LOW),
    "gdpr":         (CAT_CONSENT, "GDPR-applies flag (0/1)",                                            IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "IAB TCF consent string",                                             IMPACT_LOW),
    "us_privacy":   (CAT_CONSENT, "IAB CCPA US-privacy string",                                         IMPACT_LOW),
}


@register
class YahooAdsModule(TrackerModule):
    """Detect Yahoo Ads cookie-sync and user-profile-sync traffic."""

    module_id = "yahoo_ads"
    module_name = "Yahoo Ads"
    vendor = "Yahoo Inc. (owned by Apollo Global Management)"
    legal_jurisdiction = "US"
    data_residency = "US (New York, NY HQ); global serving infrastructure"
    sovereignty_notes = (
        "US CLOUD Act / FISA 702 apply; ownership by Apollo Global Management "
        "since 2021 (Verizon spin-off)"
    )
    # DSP / ad exchange (Right Media successor): privacy 4.0 (cross-site
    #   ad profile), security 4.0 (auction + sync chain — rubric 4.0),
    #   resilience 2.5 (US, replaceable). SSP shape.
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=2.5)
    impact_notes = {
        "privacy": "A DSP / ad exchange joining this visit to a web-wide "
            "advertising profile — cross-site by design.",
        "security": "Auctions and a sync chain redirect the visitor into "
            "demand partners you cannot enumerate.",
        "resilience": "A US ad-revenue dependency, replaceable but "
            "foreign-controlled.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _HOST_EXACTS:
            return True
        return any(host.endswith(s) for s in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []

        from urllib.parse import urlparse
        path = urlparse(event.url).path
        ups_match = _UPS_PATH_RE.match(path)
        if ups_match:
            params.append(
                ParamInfo(
                    key="(path) advertiser_id",
                    value=ups_match.group(1),
                    category=CAT_TECHNICAL,
                    meaning="Yahoo advertiser ID embedded in the URL path",
                    privacy_impact=IMPACT_LOW,
                    event_index=event.event_id,
                )
            )

        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Yahoo Ads parameter", IMPACT_LOW)
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
