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

"""Zyro / Hostinger Website Builder platform-infrastructure detector.

A site built on Zyro — now **Hostinger Website Builder** (Zyro merged
into Hostinger in April 2024; ``zyrosite.com`` still serves existing
sites) — loads its media from ``assets.zyrosite.com`` (images via a
Cloudflare ``cdn-cgi/image`` edge) and its web fonts from
``cdn.zyrosite.com`` (a Google-Fonts proxy). Hostinger International Ltd
is based in Lithuania (EU). On the wire only asset/media/font traffic is
observed — no executable JavaScript and no telemetry beacon — so this
presents as an asset CDN, with the site runtime served from the
first-party domain. This module claims the ``zyrosite.com`` requests
(classifying their parameters as technical) so they no longer fall
through to ``unclassified_hosts``.

Scoring (``ImpactRating(1.0, 1.0, 2.0)``): privacy 1.0 — a presence leak
on each media/font fetch, no tracking payload; security 1.0 — only fonts
and images are served (no executable JavaScript into the origin: the
font/image-CDN class, not the runtime-JS builder class); resilience 2.0
— an EU-controlled (Hostinger, Lithuania) asset/media dependency, no
third-country transfer concern and the assets are replaceable.
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


_HOST_SUFFIX = ".zyrosite.com"


@register
class ZyroModule(TrackerModule):
    """Detect Zyro / Hostinger Website Builder asset-CDN requests."""

    module_id = "zyro"
    module_name = "Zyro / Hostinger"
    vendor = "Hostinger International Ltd"
    legal_jurisdiction = "LT"
    data_residency = "EU (Hostinger, Lithuania); Cloudflare image edge"
    sovereignty_notes = "EU controller — no third-country transfer concern"
    impact_rating = ImpactRating(privacy=1.0, security=1.0, resilience=2.0)
    impact_notes = {
        "resilience": "An EU-controlled (Hostinger, Lithuania) asset/media "
            "dependency — replaceable, no third-country transfer concern.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return event.host.lower().endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params = [
            ParamInfo(
                key=key, value=value, category=CAT_TECHNICAL,
                meaning="Zyro / Hostinger asset/font parameter",
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
