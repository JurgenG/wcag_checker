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

"""Weebly (Square) platform-infrastructure detector.

A site built on Weebly loads its scripts, styles and images from
Weebly's exclusive asset CDN ``*.editmysite.com`` (``cdn1`` … ``cdn11``)
and its app/marketing endpoints on ``www.weebly.com``. Weebly is owned
by Square (Block, Inc., US). Only asset/app traffic is observed — no
third-party telemetry beacon — so this module claims those requests
(classifying their parameters as technical) and they no longer fall
through to ``unclassified_hosts``. It deliberately does NOT claim a
hosted ``<site>.weebly.com`` content host, which is first-party.

Scoring (``ImpactRating(1.0, 2.5, 3.0)``): privacy 1.0 — asset fetches
only, a presence leak with no observed visitor telemetry; security 2.5 —
the CDN serves the site's runtime JavaScript unpinned into the origin;
resilience 3.0 — the whole site is locked to a single foreign SaaS whose
exclusive CDN cannot be self-hosted or swapped without rebuilding.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIX = ".editmysite.com"
_HOST_EXACT = frozenset({"www.weebly.com", "weebly.com"})


@register
class WeeblyModule(TrackerModule):
    """Detect Weebly (Square) platform CDN / app requests."""

    module_id = "weebly"
    module_name = "Weebly"
    vendor = "Weebly, Inc. (Block, Inc.)"
    legal_jurisdiction = "US"
    data_residency = "US (Square / Block, Inc.); global CDN edge"
    sovereignty_notes = "First-party hosting platform; US CLOUD Act applies"
    impact_rating = ImpactRating(privacy=1.0, security=2.5, resilience=3.0)
    impact_notes = {
        "security": "The Weebly CDN serves the site's runtime JavaScript "
            "unpinned into the origin — a platform compromise would run as "
            "the site.",
        "resilience": "The whole site is locked to a single foreign SaaS "
            "whose exclusive CDN cannot be self-hosted or swapped without "
            "rebuilding.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host in _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params = [
            ParamInfo(
                key=key, value=value, category=CAT_TECHNICAL,
                meaning="Weebly platform asset/app parameter",
                privacy_impact=IMPACT_LOW, event_index=event.event_id,
            )
            for key, value in event.all_params.items()
        ]
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
