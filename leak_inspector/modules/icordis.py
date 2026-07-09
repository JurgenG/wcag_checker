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

"""Icordis / LCP detector — Belgian municipal-CMS asset hosts.

LCP builds a large share of Belgian municipal sites on the Icordis CMS,
serving fonts, icons, scripts, a chatbot proxy and other assets from
``*.icordis.be`` (``fonts.``, ``icons.``, ``static.``, ``cdn.``,
``chatbotproxy.``). The vendor is **Belgian (EU)**, so — unlike the US
asset CDNs — it draws *no* resilience / sovereignty penalty: a site
served by a decentralised EU vendor rather than US big tech is the
posture this project encourages.

It is still a third-party dependency the visitor's browser contacts, so
classifying it (rather than leaving it "unclassified") earns the same
small privacy module-count cost every third-party vendor does — the
fetch still discloses the visitor's IP / ``User-Agent`` / ``Referer``,
just to an EU controller. Requests carry no tracking parameters; any
URL params are surfaced as ``CAT_OTHER`` so they stay inspectable.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_OTHER,
    Hit,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_EXACT = "icordis.be"
_HOST_SUFFIX = ".icordis.be"


@register
class IcordisModule(TrackerModule):
    """Detect Icordis / LCP municipal-CMS asset fetches (EU vendor)."""

    module_id = "icordis"
    module_name = "Icordis (LCP)"
    vendor = "LCP"
    legal_jurisdiction = "BE"
    data_residency = "EU (Belgium)"
    sovereignty_notes = ""
    # The operator's own EU supplier throughout (proposal anchor):
    # privacy 0.5 (connection metadata to a contractual EU asset host
    # serving only this operator family — rubric privacy 0.5); security
    # 0.5 (static assets: fonts/icons/CSS, no executable threat beyond
    # defacement — rubric 0.5); resilience 0.5 (commodity EU supplier,
    # operator-substitutable — rubric 0.5).
    impact_rating = ImpactRating(privacy=0.5, security=0.5, resilience=0.5)

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            params.append(
                ParamInfo(
                    key=key,
                    value=value,
                    category=CAT_OTHER,
                    meaning="Asset-fetch URL parameter (not a tracking field)",
                    privacy_impact=IMPACT_LOW,
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
