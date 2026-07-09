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

"""AdRoll (NextRoll) retargeting detector.

NextRoll, Inc. (San Francisco, US) runs the AdRoll retargeting platform.
Its observed footprint is the ``roundtrip.js`` loader on ``s.adroll.com``
and the tracking/cookie-matching endpoints on ``d.adroll.com``
(``/consent/check``, ``/segment/<advertiser>/<segment>``,
``/cm/<partner>/out``). AdRoll is the engine that initiates the visit's
ID-sync chain — its ``/cm/.../out`` hops 302-redirect the visitor into
demand partners (Eyeota, BidSwitch, Tapad, …) the operator cannot
enumerate.

Recognized hosts: any subdomain of ``adroll.com``.
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


_HOST_SUFFIX = ".adroll.com"
_HOST_EXACT = "adroll.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "adroll_fpc":  (CAT_IDENTIFIER, "AdRoll first-party-cookie visitor identifier", IMPACT_MEDIUM),
    "advertisable": (CAT_TECHNICAL, "AdRoll advertiser account identifier", IMPACT_LOW),
    "arrfrr":      (CAT_CONTENT,    "Referring page URL the visitor came from", IMPACT_MEDIUM),
}


@register
class AdRollModule(TrackerModule):
    """Detect AdRoll (NextRoll) retargeting and cookie-matching traffic."""

    module_id = "adroll"
    module_name = "AdRoll (NextRoll)"
    vendor = "NextRoll, Inc."
    legal_jurisdiction = "US"
    data_residency = "US (San Francisco, CA HQ); global serving infrastructure"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Retargeting platform (the ad-tech sync shape): privacy 4.0 (joins the
    #   visit to a web-wide retargeting profile via a first-party-cookie id),
    #   security 4.0 (loads roundtrip.js into the origin AND its /cm/.../out
    #   redirects hop into demand partners the operator cannot enumerate),
    #   resilience 2.5 (US, replaceable ad-revenue feature).
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=2.5)
    impact_notes = {
        "privacy": "Joins this visit to a web-wide retargeting profile via "
            "a first-party-cookie identifier — cross-site by design.",
        "security": "Loads an unpinned script into your origin and its "
            "cookie-match redirects hop the visitor into demand partners "
            "you cannot enumerate.",
        "resilience": "A US ad-revenue dependency, replaceable but "
            "foreign-controlled.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized AdRoll parameter", IMPACT_LOW)
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