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

"""UserWay accessibility-overlay detector.

UserWay Inc. (Wilmington, Delaware, US) provides an accessibility-overlay
widget that injects an adjustment toolbar (contrast, font size,
screen-reader help) into the page. The widget loads ``widget.js`` from
``cdn.userway.org`` and talks to ``api.userway.org``. As an overlay it
reads and rewrites the page DOM and runs unpinned third-party JavaScript
in the origin.

Recognized hosts: any subdomain of ``userway.org``. The only observed
query parameter is the ``v`` version tag, surfaced unclassified.
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


_HOST_SUFFIX = ".userway.org"
_HOST_EXACT = "userway.org"


@register
class UserWayModule(TrackerModule):
    """Detect UserWay accessibility-overlay widget traffic."""

    module_id = "userway"
    module_name = "UserWay"
    vendor = "UserWay Inc."
    legal_jurisdiction = "US"
    data_residency = "US (Wilmington, DE); UserWay global infrastructure"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Accessibility-overlay widget (US vendor): privacy 1.5 (reads the page
    #   DOM + a presence signal; contained, not cross-site ad tracking),
    #   security 2.5 (unpinned third-party JS in the origin that rewrites
    #   the DOM — the accessibility-widget class burned by the 2018
    #   Browsealoud supply-chain attack), resilience 2.5 (US vendor for a
    #   replaceable supporting feature).
    impact_rating = ImpactRating(privacy=1.5, security=2.5, resilience=2.5)
    impact_notes = {
        "privacy": "The overlay reads (and rewrites) the page DOM and "
            "signals presence to UserWay — contained, not a cross-site "
            "tracker.",
        "security": "Runs unpinned third-party JavaScript that rewrites "
            "your DOM — the accessibility-widget class burned by the 2018 "
            "Browsealoud supply-chain compromise.",
        "resilience": "A US vendor for a replaceable supporting feature.",
    }

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
                    meaning="UserWay widget parameter — unclassified",
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
