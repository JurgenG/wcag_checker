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

"""Azure CDN / Front Door asset-host detector.

``*.azureedge.net`` is the endpoint domain for Microsoft's Azure CDN
(classic) / Front Door. Sites front their own static assets and app
APIs through it (paths like ``/static/css/main.css``, ``/static/js/
main.js``, ``/api/config/…``), so each host is typically a per-site
endpoint serving the operator's *own* content from Microsoft's US edge.

Like the other asset CDNs (see :mod:`.cloudflare_cdn`,
:mod:`.microsoft_onecdn`) it carries no tracking parameters, but it ships
**executable JavaScript** into the page from a **US** company — so the
privacy event is the fetch itself (IP / ``User-Agent`` / ``Referer``
disclosed) and the US jurisdiction feeds the resilience / sovereignty
tally.
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


_HOST_SUFFIX = ".azureedge.net"


@register
class AzureCDNModule(TrackerModule):
    """Detect Azure CDN / Front Door asset fetches (US-operated edge)."""

    module_id = "azure_cdn"
    module_name = "Azure CDN"
    vendor = "Microsoft Corporation"
    legal_jurisdiction = "US"
    data_residency = "Microsoft Azure global edge; US controller"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Asset CDN serving the operator's own JS/CSS/app APIs from Azure's
    #   edge: privacy 1.0 (presence leak only), security 2.5 (unpinned
    #   executable JS into the origin — same class as cloudflare_cdn /
    #   google_cdn / microsoft_onecdn 2.5), resilience 2.0 (US-controlled
    #   asset host, replaceable / self-hostable).
    impact_rating = ImpactRating(privacy=1.0, security=2.5, resilience=2.0)
    impact_notes = {
        "security": "Serves JavaScript into the page from Azure's edge "
            "unpinned — a CDN compromise would run as the site.",
        "resilience": "A US-controlled (Microsoft Azure) asset host for "
            "the operator's own, self-hostable content.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return event.host.lower().endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = [
            ParamInfo(
                key=key,
                value=value,
                category=CAT_OTHER,
                meaning="Asset-fetch URL parameter (not a tracking field)",
                privacy_impact=IMPACT_LOW,
                event_index=event.event_id,
            )
            for key, value in event.all_params.items()
        ]
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
