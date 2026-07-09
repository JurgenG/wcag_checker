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

"""Eyeota (Dun & Bradstreet) audience ID-sync detector.

Eyeota (owned by Dun & Bradstreet, US) is an audience-data provider. Its
observed footprint is the cookie-sync endpoint on ``ps.eyeota.net``
(``/match`` with ``bid`` + ``uid``) — a sync hop that matches the
visitor's id into Eyeota's audience-segment graph for ad targeting.

Recognized hosts: any subdomain of ``eyeota.net``.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_CONSENT,
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


_HOST_SUFFIX = ".eyeota.net"
_HOST_EXACT = "eyeota.net"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "uid":  (CAT_IDENTIFIER, "Visitor id synced into Eyeota's audience graph", IMPACT_MEDIUM),
    "bid":  (CAT_TECHNICAL,  "Eyeota buyer / segment identifier", IMPACT_LOW),
    "gdpr":         (CAT_CONSENT, "IAB TCF: GDPR-applies flag", IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "IAB TCF consent string", IMPACT_LOW),
}


@register
class EyeotaModule(TrackerModule):
    """Detect Eyeota (Dun & Bradstreet) audience cookie-sync traffic."""

    module_id = "eyeota"
    module_name = "Eyeota (Dun & Bradstreet)"
    vendor = "Eyeota (Dun & Bradstreet, Inc.)"
    legal_jurisdiction = "US"
    data_residency = "US controller (Dun & Bradstreet); global serving"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Audience-data cookie sync (the ad-tech sync shape): privacy 4.0
    #   (joins the visit to a web-wide audience-segment graph), security 4.0
    #   (the /match redirect hops into partners the operator cannot
    #   enumerate), resilience 2.5 (US controller, replaceable ad feature).
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=2.5)
    impact_notes = {
        "privacy": "A cookie-sync that joins this visit to a web-wide "
            "audience-segment profile — cross-site by design.",
        "security": "The cookie-sync redirect hops the visitor into partners "
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
                key, (CAT_OTHER, "Unrecognized Eyeota parameter", IMPACT_LOW)
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