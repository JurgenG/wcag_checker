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

"""Tribal Fusion / Exponential Interactive detector.

Exponential Interactive, Inc. (Emeryville, CA, US) runs the Tribal
Fusion ad network. Its web footprint observed in captures is the
**cookie-sync** endpoint on ``a.tribalfusion.com`` / ``s.tribalfusion.com``
(``/i.match?p=<partner>&redirect=<downstream pixel>``) — a sync hop that
matches the visitor's Tribal Fusion id and 302-redirects into a demand
partner (e.g. PubMatic), i.e. a transitive fourth party the operator
cannot enumerate.

Recognized hosts: any subdomain of ``tribalfusion.com``.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_CONTENT,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIX = ".tribalfusion.com"
_HOST_EXACT = "tribalfusion.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "p":        (CAT_TECHNICAL, "Partner / payload tag for the cookie-sync", IMPACT_LOW),
    "redirect": (CAT_CONTENT,   "Downstream sync target (the next vendor in the ID-sync hop)", IMPACT_MEDIUM),
}


@register
class TribalFusionModule(TrackerModule):
    """Detect Tribal Fusion (Exponential Interactive) cookie-sync traffic."""

    module_id = "tribalfusion"
    module_name = "Tribal Fusion (Exponential)"
    vendor = "Exponential Interactive, Inc."
    legal_jurisdiction = "US"
    data_residency = "US (Emeryville, CA HQ); global serving infrastructure"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Cookie-sync ad network (the ad-tech sync shape): privacy 4.0
    #   (cross-site ad profile, the sync joins the visit to a web-wide
    #   graph), security 4.0 (the /i.match redirect chain hops into demand
    #   partners the operator cannot enumerate — transitive fourth parties),
    #   resilience 2.5 (US, replaceable ad-revenue supporting feature).
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=2.5)
    impact_notes = {
        "privacy": "A cookie-sync that joins this visit to a web-wide "
            "advertising profile — cross-site by design.",
        "security": "The cookie-sync redirect chain hops the visitor into "
            "demand partners you cannot enumerate.",
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
                key, (CAT_OTHER, "Unrecognized Tribal Fusion parameter", IMPACT_LOW)
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
