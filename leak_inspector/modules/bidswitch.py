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

"""BidSwitch (IPONWEB / Criteo) ID-sync detector.

BidSwitch is a programmatic supply/demand bridge operated by IPONWEB,
which is owned by Criteo S.A. (Paris, France). Its observed footprint is
the cookie-sync endpoint on ``x.bidswitch.net`` (``/sync`` with
``dsp_id`` + ``user_id``) — a sync hop that maps the visitor's id into a
demand-side platform across the BidSwitch network.

Recognized hosts: any subdomain of ``bidswitch.net``.
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


_HOST_SUFFIX = ".bidswitch.net"
_HOST_EXACT = "bidswitch.net"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "user_id": (CAT_IDENTIFIER, "Visitor id synced across the BidSwitch network", IMPACT_MEDIUM),
    "dsp_id":  (CAT_TECHNICAL,  "Demand-side-platform identifier for the sync target", IMPACT_LOW),
    "gdpr":         (CAT_CONSENT, "IAB TCF: GDPR-applies flag", IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "IAB TCF consent string", IMPACT_LOW),
}


@register
class BidSwitchModule(TrackerModule):
    """Detect BidSwitch (IPONWEB / Criteo) cookie-sync traffic."""

    module_id = "bidswitch"
    module_name = "BidSwitch (IPONWEB)"
    vendor = "IPONWEB (Criteo S.A.)"
    legal_jurisdiction = "FR"
    data_residency = "EU controller (Criteo S.A., France); global serving"
    sovereignty_notes = "EU controller — no third-country transfer to the controller"
    # Programmatic sync bridge (the ad-tech sync shape, EU-controlled):
    #   privacy 4.0 (joins the visit to a web-wide bidding graph), security
    #   4.0 (the /sync redirect hops into DSPs the operator cannot
    #   enumerate), resilience 1.5 (EU controller — matches criteo.py; lower
    #   sovereignty exposure than a US ad dependency).
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=1.5)
    impact_notes = {
        "privacy": "A cookie-sync that joins this visit to a web-wide "
            "programmatic-bidding graph — cross-site by design.",
        "security": "The cookie-sync redirect hops the visitor into "
            "demand-side platforms you cannot enumerate.",
        "resilience": "An EU-controlled (Criteo) ad dependency — replaceable, "
            "lower sovereignty exposure than a US one.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized BidSwitch parameter", IMPACT_LOW)
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