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

"""TripleLift native-advertising SSP detector.

TripleLift runs a native-advertising-focused supply-side platform.
The pixel calls observed on publisher pages perform open-RTB
cookie-sync, minting a TripleLift visitor ID and chaining onward to
DMPs / DSPs via the ``redir`` parameter.

Recognized hosts: ``*.3lift.com`` (incl. ``dmpsync.3lift.com``,
``eb2.3lift.com``, ``ib.3lift.com``). Notable paths:

* ``/getuid`` — cookie-sync endpoint; mints a TripleLift UID and
  302-redirects the client to ``?redir=...``.
* ``/sync`` — JSON cookie-sync alternative.
* ``/auction`` — auction-side endpoints (rare on publisher pages).
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
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIX = ".3lift.com"
_HOST_EXACT = "3lift.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    # --- sync targets ---
    "tl_uid":    (CAT_IDENTIFIER, "TripleLift visitor pseudonym",                 IMPACT_HIGH),
    "uid":       (CAT_IDENTIFIER, "Partner / vendor user ID",                     IMPACT_HIGH),
    "pid":       (CAT_TECHNICAL, "Partner ID",                                    IMPACT_LOW),
    # --- redirect chain ---
    "redir":     (CAT_TECHNICAL, "Redirect target (next vendor in ID-sync hop)",  IMPACT_LOW),
    "r":         (CAT_TECHNICAL, "Redirect target (alt form)",                    IMPACT_LOW),
    # --- consent ---
    "gdpr":         (CAT_CONSENT, "GDPR-applies flag (0/1)",                       IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "IAB TCF consent string",                        IMPACT_LOW),
    "us_privacy":   (CAT_CONSENT, "IAB CCPA US-privacy string",                    IMPACT_LOW),
}


@register
class TripleLiftModule(TrackerModule):
    """Detect TripleLift native-SSP cookie-sync traffic."""

    module_id = "triplelift"
    module_name = "TripleLift"
    vendor = "TripleLift, Inc."
    legal_jurisdiction = "US"
    data_residency = "US (New York, NY HQ); global serving infrastructure"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Native-ad SSP: privacy 4.0 / security 4.0 (OpenRTB sync chain) /
    # resilience 2.5 (US). SSP shape — see appnexus.
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=2.5)
    impact_notes = {
        "privacy": "A native-ad SSP joining this visit to a web-wide "
            "advertising profile — cross-site by design.",
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
                key, (CAT_OTHER, "Unrecognized TripleLift parameter", IMPACT_LOW)
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
