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

"""jQuery CDN detector.

``code.jquery.com`` is the official jQuery CDN — the library is the
OpenJS Foundation's, but the CDN is served by StackPath (a US company),
so every fetch hands the visitor's IP / ``User-Agent`` / ``Referer`` to
a US-jurisdiction operator. Like cdnjs / unpkg it serves **unpinned
JavaScript** into the page origin.

Recognized host: ``code.jquery.com``.
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


_HOST_EXACT = "code.jquery.com"


@register
class JQueryCDNModule(TrackerModule):
    """Detect jQuery CDN (code.jquery.com) asset fetches."""

    module_id = "jquery_cdn"
    module_name = "jQuery CDN"
    vendor = "jQuery / OpenJS Foundation (CDN served by StackPath)"
    legal_jurisdiction = "US"
    data_residency = "StackPath CDN edge (US-jurisdiction operator)"
    sovereignty_notes = (
        "The library is the OpenJS Foundation's, but code.jquery.com is "
        "served by StackPath (US) — US CLOUD Act / FISA 702 apply to the "
        "edge that receives the visitor's IP"
    )
    # JS library CDN (like cdnjs / unpkg): privacy 1.0 (presence leak),
    #   security 2.5 (unpinned executable JS into the origin — a CDN
    #   compromise runs as your site), resilience 2.0 (US-served,
    #   replaceable library host).
    impact_rating = ImpactRating(privacy=1.0, security=2.5, resilience=2.0)
    impact_notes = {
        "security": "Serves jQuery into your origin unpinned — a CDN "
            "compromise would run as your site.",
        "resilience": "A US-served asset host for a replaceable library.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return event.host.lower() == _HOST_EXACT

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
