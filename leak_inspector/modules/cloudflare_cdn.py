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

"""Cloudflare cdnjs asset-CDN detector.

``cdnjs.cloudflare.com`` is the Cloudflare-operated public CDN for
JavaScript / CSS libraries (jQuery, Bootstrap, …). Like the Google
asset hosts (see :mod:`.google_cdn`), it carries no tracking
parameters — but every fetch hands the visitor's IP, ``User-Agent``
and ``Referer`` to a **US** company, so the privacy event is *the fetch
itself*, and the US jurisdiction feeds the resilience / sovereignty
exposure tally.

Scope is deliberately narrow: only the ``cdnjs`` asset host. Cloudflare's
other products that this project recognises (Web Analytics, Turnstile,
Zaraz) have their own dedicated modules.
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


_HOST_EXACT = "cdnjs.cloudflare.com"


@register
class CloudflareCDNModule(TrackerModule):
    """Detect Cloudflare cdnjs asset fetches (US-operated library CDN)."""

    module_id = "cloudflare_cdn"
    module_name = "Cloudflare CDN (cdnjs)"
    vendor = "Cloudflare, Inc."
    legal_jurisdiction = "US"
    data_residency = "US (San Francisco, CA HQ); Cloudflare global edge"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # cdnjs asset CDN serving JS libraries: privacy 1.0 (presence leak),
    #   security 2.5 (unpinned executable JS into the origin), resilience
    #   2.0 (US, replaceable library host — rubric 2.0).
    impact_rating = ImpactRating(privacy=1.0, security=2.5, resilience=2.0)
    impact_notes = {
        "security": "Serves JavaScript libraries (cdnjs) into your origin "
            "unpinned — a CDN compromise would run as your site.",
        "resilience": "A US-controlled asset host for replaceable "
            "libraries.",
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
