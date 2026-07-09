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

"""OpenX SSP detector.

OpenX runs a programmatic ad exchange / SSP. It participates in the
open-RTB cookie-sync chain and sets a persistent ``OX-uid`` cookie
keyed to the visitor's browser.

Recognized hosts: ``*.openx.net`` (incl. regional ``us-u.openx.net``,
``eu-u.openx.net``, ``rtb.openx.net``). Notable paths:

* ``/w/1.0/sd`` — set-data: persist a partner-supplied value as the
  OpenX visitor pseudonym.
* ``/cs/v1/sync`` — JSON cookie-sync handler.
* ``/w/1.0/cm`` — cookie-match endpoint.
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
    IMPACT_HIGH,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIX = ".openx.net"
_HOST_EXACT = "openx.net"


_PARAMS: dict[str, tuple[str, str, str]] = {
    # --- sync targets ---
    "id":        (CAT_TECHNICAL,  "OpenX partner / seat ID",                         IMPACT_LOW),
    "val":       (CAT_IDENTIFIER, "Value to persist (partner-supplied user ID)",     IMPACT_HIGH),
    "pid":       (CAT_TECHNICAL,  "Partner ID (alt form)",                            IMPACT_LOW),
    # --- redirect chain ---
    "r":         (CAT_TECHNICAL, "Redirect target after sync completes",              IMPACT_LOW),
    "redir":     (CAT_TECHNICAL, "Redirect target (alt form)",                        IMPACT_LOW),
    # --- consent ---
    "gdpr":         (CAT_CONSENT, "GDPR-applies flag (0/1)",                          IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "IAB TCF consent string",                           IMPACT_LOW),
    "us_privacy":   (CAT_CONSENT, "IAB CCPA US-privacy string",                       IMPACT_LOW),
}


@register
class OpenXModule(TrackerModule):
    """Detect OpenX SSP cookie-sync and set-data traffic."""

    module_id = "openx"
    module_name = "OpenX"
    vendor = "OpenX Software Ltd."
    legal_jurisdiction = "US"
    data_residency = "US (Pasadena, CA HQ); regional ingest (us-u, eu-u, ap-u, …)"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # SSP: privacy 4.0 (cross-site, persistent OX-uid), security 4.0
    # (OpenRTB sync chain), resilience 2.5 (US supporting). See appnexus.
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=2.5)
    impact_notes = {
        "privacy": "An SSP with a persistent OX-uid that joins this visit "
            "to a web-wide advertising profile — cross-site by design.",
        "security": "OpenRTB auctions and a sync chain redirect the "
            "visitor into demand partners you cannot enumerate.",
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
                key, (CAT_OTHER, "Unrecognized OpenX parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key,
                    value=value,
                    category=category,
                    meaning=meaning,
                    privacy_impact=impact,
                    event_index=event.event_id,
                )
            )
        return Hit(
            module_id=self.module_id,
            module_name=self.module_name,
            url=event.url,
            host=event.host,
            method=event.method,
            response_status=event.response_status,
            started_at=event.timestamp,
            params=params,
            events=[event.event_id],
        )
