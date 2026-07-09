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

"""Integral Ad Science (IAS) detector.

IAS is a third-party ad-verification vendor: brand safety, viewability,
invalid-traffic (IVT) detection, and ad-fraud measurement.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
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


_HOST_SUFFIX = ".adsafeprotected.com"
_HOST_EXACT = "adsafeprotected.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "ias_campId":      (CAT_TECHNICAL, "IAS campaign ID",                             IMPACT_LOW),
    "ias_creativeId":  (CAT_TECHNICAL, "IAS creative ID",                             IMPACT_LOW),
    "ias_placementId": (CAT_TECHNICAL, "IAS placement / ad-slot ID",                  IMPACT_LOW),
    "ias_impId":       (CAT_IDENTIFIER, "IAS impression ID (numeric, varies per request)", IMPACT_LOW),
    "advEntityId":     (CAT_TECHNICAL, "IAS account entity ID",                       IMPACT_LOW),
    "asId":            (CAT_IDENTIFIER, "Ad-serve ID (UUID, varies per request)",     IMPACT_LOW),
    "cbName": (CAT_TECHNICAL, "JSONP callback function name",                         IMPACT_LOW),
    "adsafe_url": (CAT_CONTENT, "Page URL the ad rendered on",                        IMPACT_MEDIUM),
    "adsafe_jsinfo": (CAT_TECHNICAL, "Client viewability-state envelope (carries ``asId`` + state codes)", IMPACT_MEDIUM),
}


@register
class IntegralAdScienceModule(TrackerModule):
    """Detect Integral Ad Science viewability / brand-safety / IVT traffic."""

    module_id = "integral_ad_science"
    module_name = "Integral Ad Science"
    vendor = "Integral Ad Science Holding Corp."
    legal_jurisdiction = "US"
    data_residency = "US headquarters; global serving infrastructure"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Ad-verification (viewability / IVT / fraud), not an audience builder:
    # privacy 3.0 (behavioural/device signal at a self-interested
    #   controller — rubric 3.0, below the cross-site-by-design 4.0 of the
    #   SSPs). security 2.5 (ordinary unpinned measurement script).
    # resilience 2.5 (US supporting measurement feature).
    impact_rating = ImpactRating(privacy=3.0, security=2.5, resilience=2.5)
    impact_notes = {
        "privacy": "Ad-verification (viewability / fraud) collects a "
            "behavioural/device signal at a self-interested controller — "
            "but does not build a cross-site ad audience.",
        "security": "Loads an unpinned measurement script into your "
            "origin.",
        "resilience": "A US measurement vendor — replaceable supporting "
            "feature.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized IAS parameter", IMPACT_LOW)
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
