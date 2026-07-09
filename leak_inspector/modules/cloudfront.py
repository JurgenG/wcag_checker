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

"""Amazon CloudFront asset-CDN detector.

``*.cloudfront.net`` is the endpoint domain for Amazon CloudFront, AWS's
content-delivery network. Each ``<distribution>.cloudfront.net`` host
fronts some operator's or vendor's assets (observed serving site images
and JavaScript such as a hosted jQuery). It carries no tracking
parameters, but every fetch hands the visitor's IP / ``User-Agent`` /
``Referer`` to a **US** company, and CloudFront distributions routinely
serve **executable JavaScript** into the page — so the privacy event is
the fetch itself and the US jurisdiction feeds the resilience tally.
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


_HOST_SUFFIX = ".cloudfront.net"


@register
class CloudFrontModule(TrackerModule):
    """Detect Amazon CloudFront asset fetches (US-operated CDN)."""

    module_id = "cloudfront"
    module_name = "Amazon CloudFront"
    vendor = "Amazon.com, Inc. (AWS)"
    legal_jurisdiction = "US"
    data_residency = "AWS global edge; US controller"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Asset CDN serving JS/images from AWS's edge: privacy 1.0 (presence
    #   leak), security 2.5 (unpinned executable JS into the origin — same
    #   class as cloudflare_cdn / google_cdn / azure_cdn 2.5), resilience
    #   2.0 (US-controlled asset host, replaceable / self-hostable).
    impact_rating = ImpactRating(privacy=1.0, security=2.5, resilience=2.0)
    impact_notes = {
        "security": "CloudFront distributions serve JavaScript into the "
            "page unpinned — a distribution compromise would run as the "
            "site.",
        "resilience": "A US-controlled (AWS) asset host for replaceable / "
            "self-hostable content.",
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
