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

"""Bombora (ml314.com) B2B intent ID-sync detector.

Bombora, Inc. (New York, US) is a B2B intent-data aggregator; its
tracking domain is ``ml314.com``. The observed footprint is the
cookie-sync endpoint ``/utsync.ashx`` (with ``eid`` + ``fp``) — a sync
hop that maps the visitor's id into Bombora's B2B-intent co-op for
targeting.

Recognized hosts: ``ml314.com`` and any of its subdomains.
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


_HOST_SUFFIX = ".ml314.com"
_HOST_EXACT = "ml314.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "fp":   (CAT_IDENTIFIER, "Visitor id synced into Bombora's intent co-op", IMPACT_MEDIUM),
    "eid":  (CAT_TECHNICAL,  "Bombora entity / tag identifier", IMPACT_LOW),
    "et":   (CAT_TECHNICAL,  "Bombora sync event-type flag", IMPACT_LOW),
    "gdpr":         (CAT_CONSENT, "IAB TCF: GDPR-applies flag", IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "IAB TCF consent string", IMPACT_LOW),
}


@register
class BomboraModule(TrackerModule):
    """Detect Bombora (ml314.com) B2B-intent cookie-sync traffic."""

    module_id = "bombora"
    module_name = "Bombora"
    vendor = "Bombora, Inc."
    legal_jurisdiction = "US"
    data_residency = "US (New York HQ); global serving infrastructure"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # B2B-intent cookie sync (the ad-tech sync shape): privacy 4.0 (joins
    #   the visit to a web-wide B2B-intent co-op), security 4.0 (the
    #   /utsync.ashx redirect hops into partners the operator cannot
    #   enumerate), resilience 2.5 (US, replaceable ad feature).
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=2.5)
    impact_notes = {
        "privacy": "A cookie-sync that joins this visit to a web-wide "
            "B2B-intent data co-op — cross-site by design.",
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
                key, (CAT_OTHER, "Unrecognized Bombora parameter", IMPACT_LOW)
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