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

"""BootstrapCDN detector.

``*.bootstrapcdn.com`` (``maxcdn.``, ``stackpath.``, ``netdna.``) is the
public CDN for Bootstrap CSS/JS and other front-end libraries, operated
by StackPath (US; founded at MaxCDN). The serving was moved under
jsDelivr in 2021, but the legacy ``bootstrapcdn.com`` hosts remain in
wide use. Like cdnjs it serves **unpinned JavaScript / CSS** into the
origin, and the fetch hands the visitor's IP / ``User-Agent`` /
``Referer`` to a US operator.

Recognized hosts: any subdomain of ``bootstrapcdn.com``.
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


_HOST_SUFFIX = ".bootstrapcdn.com"
_HOST_EXACT = "bootstrapcdn.com"


@register
class BootstrapCDNModule(TrackerModule):
    """Detect BootstrapCDN asset fetches (US-operated library CDN)."""

    module_id = "bootstrapcdn"
    module_name = "BootstrapCDN"
    vendor = "StackPath (BootstrapCDN)"
    legal_jurisdiction = "US"
    data_residency = "StackPath CDN edge (US-jurisdiction operator)"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # JS/CSS library CDN (like cdnjs): privacy 1.0 (presence leak), security
    #   2.5 (unpinned executable JS into the origin), resilience 2.0 (US,
    #   replaceable library host).
    impact_rating = ImpactRating(privacy=1.0, security=2.5, resilience=2.0)
    impact_notes = {
        "security": "Serves Bootstrap / library JavaScript into your origin "
            "unpinned — a CDN compromise would run as your site.",
        "resilience": "A US-controlled asset host for replaceable "
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
