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

"""unpkg open-source CDN detector.

``unpkg.com`` is a free CDN that serves any file from any npm package
(``/<pkg>@<version>/<file>``). Like cdnjs / jsDelivr it carries no
tracking parameters — the privacy event is *the fetch itself* (visitor
IP / ``User-Agent`` / ``Referer``). The project is community-maintained
but runs **entirely on Cloudflare's edge** (Cloudflare Workers), so the
serving company — and the visitor's IP exposure — is US-jurisdiction.

Recognized host: ``unpkg.com`` and any subdomain (the ``app.unpkg.com``
browse UI). URLs are path-based; the only query parameter observed is
the ``ver``/cache-buster family, surfaced unclassified.
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


_HOST_SUFFIX = ".unpkg.com"
_HOST_EXACT = "unpkg.com"


@register
class UnpkgModule(TrackerModule):
    """Detect unpkg.com asset fetches (npm library CDN, served on Cloudflare)."""

    module_id = "unpkg"
    module_name = "unpkg"
    vendor = "unpkg (community project, served on Cloudflare)"
    legal_jurisdiction = "US"
    data_residency = "Cloudflare global edge (Cloudflare Workers) — US-jurisdiction operator"
    sovereignty_notes = (
        "The unpkg project is community-maintained, but it runs entirely on "
        "Cloudflare's edge, so the visitor's IP reaches Cloudflare, Inc. — "
        "US CLOUD Act / FISA 702 apply"
    )
    # npm library CDN serving unpinned JS into the origin: privacy 1.0
    #   (presence leak), security 2.5 (a CDN compromise runs as your site —
    #   same class as cdnjs / jsDelivr), resilience 2.0 (US-served,
    #   replaceable library host).
    impact_rating = ImpactRating(privacy=1.0, security=2.5, resilience=2.0)
    impact_notes = {
        "security": "Serves arbitrary npm JavaScript into your origin "
            "unpinned — a CDN compromise would run as your site.",
        "resilience": "A Cloudflare-served (US) asset host for replaceable "
            "libraries.",
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
