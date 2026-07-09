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

"""Squarespace platform-infrastructure detector.

A site built on Squarespace loads its scripts, media and component
definitions from Squarespace-owned CDNs:

* ``static1.squarespace.com`` / ``assets.squarespace.com`` — script and
  site-bundle CDN,
* ``images.squarespace-cdn.com`` / ``video.squarespace-cdn.com`` — media
  CDN,
* ``definitions.sqspcdn.com`` — component-definition CDN.

These are Squarespace's own infrastructure (Squarespace, Inc., New York,
US). Only asset/CDN traffic is observed — Squarespace's visitor
analytics is server-side, so no third-party telemetry beacon appears.
This module claims those requests (classifying their parameters as
technical) so they no longer fall through to ``unclassified_hosts``.

Scoring (``ImpactRating(1.0, 2.5, 3.0)``): privacy 1.0 — asset fetches
only, a presence leak with no observed visitor telemetry; security 2.5 —
the CDN serves the site's runtime JavaScript unpinned into the origin
(the asset-CDN class); resilience 3.0 — the whole site is locked to a
single foreign SaaS whose exclusive CDN cannot be self-hosted or swapped
without rebuilding.
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


_HOST_SUFFIXES = (".squarespace.com", ".squarespace-cdn.com", ".sqspcdn.com")


@register
class SquarespaceModule(TrackerModule):
    """Detect Squarespace platform CDN requests."""

    module_id = "squarespace"
    module_name = "Squarespace"
    vendor = "Squarespace, Inc."
    legal_jurisdiction = "US"
    data_residency = "US (New York HQ); global CDN edge"
    sovereignty_notes = "First-party hosting platform; US CLOUD Act applies"
    impact_rating = ImpactRating(privacy=1.0, security=2.5, resilience=3.0)
    impact_notes = {
        "security": "The Squarespace CDN serves the site's runtime "
            "JavaScript unpinned into the origin — a platform compromise "
            "would run as the site.",
        "resilience": "The whole site is locked to a single foreign SaaS "
            "whose exclusive CDN cannot be self-hosted or swapped without "
            "rebuilding.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return any(host.endswith(suffix) for suffix in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params = [
            ParamInfo(
                key=key, value=value, category=CAT_TECHNICAL,
                meaning="Squarespace platform asset parameter",
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
