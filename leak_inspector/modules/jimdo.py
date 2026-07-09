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

"""Jimdo (Jimdo GmbH) platform-infrastructure detector.

A site built on Jimdo loads its renderer, fonts and assets from Jimdo's
exclusive CDN ``*.jimstatic.com`` and its app / image-storage endpoints
on ``*.jimdo.com`` (``a.jimdo.com`` login-state, ``storage.e.jimdo.com``
image CDN). It also posts first-party analytics to Jimdo's beacon
``at.prod.jimdo.systems`` (``/anon``, ``/cf``). Jimdo GmbH is based in
Hamburg, Germany — an **EU** controller. This module claims those
Jimdo-owned requests so they no longer fall through to
``unclassified_hosts``.

Scoring (``ImpactRating(1.5, 2.5, 2.5)``): privacy 1.5 — the
``jimdo.systems`` analytics beacon records visitor activity (first-party
analytics by Jimdo, session-level, no durable cross-site profile);
security 2.5 — the CDN serves the site's runtime JavaScript unpinned
into the origin; resilience 2.5 — the whole site is locked to a single
SaaS, but Jimdo is EU-based, so there is no third-country transfer
concern for EU users (lower than the US/IL builders' 3.0).
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


_HOST_SUFFIXES = (".jimstatic.com", ".jimdo.com", ".jimdo.systems")


@register
class JimdoModule(TrackerModule):
    """Detect Jimdo platform CDN / app requests."""

    module_id = "jimdo"
    module_name = "Jimdo"
    vendor = "Jimdo GmbH"
    legal_jurisdiction = "DE"
    data_residency = "EU (Hamburg, Germany)"
    sovereignty_notes = "EU controller — no third-country transfer concern"
    impact_rating = ImpactRating(privacy=1.5, security=2.5, resilience=2.5)
    impact_notes = {
        "privacy": "at.prod.jimdo.systems records visitor activity (Jimdo "
            "first-party analytics); session-level, no durable cross-site "
            "profile.",
        "security": "The Jimdo CDN serves the site's runtime JavaScript "
            "unpinned into the origin — a platform compromise would run as "
            "the site.",
        "resilience": "The whole site is locked to a single SaaS; Jimdo is "
            "EU-based, so no third-country transfer, but the lock-in remains.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return any(host.endswith(suffix) for suffix in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params = [
            ParamInfo(
                key=key, value=value, category=CAT_TECHNICAL,
                meaning="Jimdo platform asset/app parameter",
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
