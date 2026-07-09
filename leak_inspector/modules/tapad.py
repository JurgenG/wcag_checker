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

"""Tapad (Experian) cross-device ID-sync detector.

Tapad, Inc. (New York, US; owned by Experian) runs a cross-device
identity graph. Its observed footprint is the cookie-sync endpoint on
``pixel.tapad.com`` (``/idsync/ex/receive`` with ``partner_id`` +
``partner_device_id``) — a sync hop that maps the visitor's id between a
partner and Tapad's graph, joining the visitor's devices into a single
cross-device profile.

Recognized hosts: any subdomain of ``tapad.com``.
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


_HOST_SUFFIX = ".tapad.com"
_HOST_EXACT = "tapad.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "partner_device_id": (CAT_IDENTIFIER, "Visitor id synced into Tapad's cross-device graph", IMPACT_MEDIUM),
    "partner_id":        (CAT_TECHNICAL,  "Tapad partner account identifier", IMPACT_LOW),
    "gdpr":         (CAT_CONSENT, "IAB TCF: GDPR-applies flag", IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "IAB TCF consent string", IMPACT_LOW),
}


@register
class TapadModule(TrackerModule):
    """Detect Tapad (Experian) cross-device cookie-sync traffic."""

    module_id = "tapad"
    module_name = "Tapad (Experian)"
    vendor = "Tapad, Inc. (Experian)"
    legal_jurisdiction = "US"
    data_residency = "US (New York HQ); Experian-owned"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Cross-device identity graph (the ad-tech sync shape, elevated
    #   privacy): privacy 4.5 (joins the visitor's *devices* into one
    #   cross-device profile — broader than a single-browser cookie sync),
    #   security 4.0 (the idsync redirect hops into partners the operator
    #   cannot enumerate), resilience 2.5 (US, replaceable ad feature).
    impact_rating = ImpactRating(privacy=4.5, security=4.0, resilience=2.5)
    impact_notes = {
        "privacy": "Maps the visitor into Experian's cross-device identity "
            "graph — links separate devices into one profile.",
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
                key, (CAT_OTHER, "Unrecognized Tapad parameter", IMPACT_LOW)
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
