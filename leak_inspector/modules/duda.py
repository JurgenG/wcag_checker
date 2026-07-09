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

"""Duda platform-infrastructure detector.

A site built on Duda loads its React runtime and assets from Duda's
exclusive CDN on `*.multiscreensite.com` (``de-ms-cdn`` / ``ms-cdn``
serve `runtime-react.js`, ``irp-cdn`` serves media) and posts
performance telemetry to ``rtc.multiscreensite.com/performance/metrics``
(regional variants prefix the registrable domain, e.g.
``rtc.eu-multiscreensite.com``). Duda, Inc. is based in Palo Alto, CA
(US). This module claims those Duda-owned requests so they no longer
fall through to ``unclassified_hosts``, classifying the ``rtc`` telemetry
fields as behavioral and the asset fields as technical.

Scoring (``ImpactRating(1.5, 2.5, 3.0)``): privacy 1.5 — the ``rtc``
beacon records performance metrics (first-party telemetry, session-level,
no durable cross-site profile); security 2.5 — the CDN serves the site's
React runtime JavaScript unpinned into the origin; resilience 3.0 — the
whole site is locked to a single foreign (US) SaaS whose exclusive
CDN/runtime cannot be self-hosted or swapped without rebuilding.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIXES = (".multiscreensite.com", "-multiscreensite.com", ".cdn-website.com")
_HOST_EXACT = "multiscreensite.com"


@register
class DudaModule(TrackerModule):
    """Detect Duda platform CDN / runtime / telemetry requests."""

    module_id = "duda"
    module_name = "Duda"
    vendor = "Duda, Inc."
    legal_jurisdiction = "US"
    data_residency = "US (Palo Alto, CA HQ); regional edges (incl. EU)"
    sovereignty_notes = "First-party hosting platform; US CLOUD Act applies"
    impact_rating = ImpactRating(privacy=1.5, security=2.5, resilience=3.0)
    impact_notes = {
        "privacy": "rtc.multiscreensite.com records performance metrics "
            "(Duda first-party telemetry); session-level, no durable "
            "cross-site profile.",
        "security": "The Duda CDN serves the site's React runtime "
            "JavaScript unpinned into the origin — a platform compromise "
            "would run as the site.",
        "resilience": "The whole site is locked to a single foreign SaaS "
            "whose exclusive CDN/runtime cannot be self-hosted or swapped "
            "without rebuilding.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or any(
            host.endswith(suffix) for suffix in _HOST_SUFFIXES
        )

    def parse(self, event: RequestEvent) -> Hit:
        telemetry = event.host.lower().startswith("rtc.")
        category = CAT_BEHAVIORAL if telemetry else CAT_TECHNICAL
        meaning = (
            "Duda performance-telemetry field" if telemetry
            else "Duda platform asset/runtime parameter"
        )
        params = [
            ParamInfo(
                key=key, value=value, category=category, meaning=meaning,
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
