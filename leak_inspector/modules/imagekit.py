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

"""ImageKit image-CDN detector.

ImageKit (ImageKit.io, headquartered in India) is a multi-tenant
image-transform / delivery CDN — the same product class as Imgix. Each
customer is served from ``ik.imagekit.io/<id>/<path>``; the image
filename is in the path and the transform in the query string. The fetch
discloses the visitor's IP / ``User-Agent`` / ``Referer``; images are
not executable.

Recognized hosts: any subdomain of ``imagekit.io``.
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


_HOST_SUFFIX = ".imagekit.io"
_HOST_EXACT = "imagekit.io"


@register
class ImageKitModule(TrackerModule):
    """Detect ImageKit image-CDN fetches."""

    module_id = "imagekit"
    module_name = "ImageKit"
    vendor = "ImageKit.io"
    legal_jurisdiction = "IN"
    data_residency = "India (HQ); ImageKit global CDN edge"
    sovereignty_notes = (
        "Indian controller (non-EU, not an EU adequacy country); data "
        "served from a non-EU image CDN"
    )
    # Image-transform CDN (like imgix): privacy 1.0 (presence leak), security
    #   0.5 (images, not executable code — no in-origin execution),
    #   resilience 2.0 (a non-EU image CDN for assets that could be served
    #   from EU / own infrastructure).
    impact_rating = ImpactRating(privacy=1.0, security=0.5, resilience=2.0)
    impact_notes = {
        "resilience": "A non-EU (Indian) image CDN for assets that could be "
            "served from EU / own infrastructure.",
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
                    meaning="Image-fetch URL parameter (not a tracking field)",
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
