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

"""Font Awesome icon-CDN detector.

Font Awesome (Fonticons, Inc., US) serves its icon stylesheet + webfonts
from the ``fontawesome.com`` CDN — ``use.fontawesome.com`` (free CDN,
``/releases/<ver>/css/all.css``) and ``pro.fontawesome.com`` (Pro). Same
privacy framing as Google Fonts / Adobe Fonts: the fetch itself hands
the visitor's IP, ``User-Agent`` and ``Referer`` to a US controller; the
delivered asset is a *stylesheet* + font binaries, not executable JS.

Recognized hosts: any subdomain of ``fontawesome.com``. URLs are
path-based; the only observed query parameter is the ``ver``
cache-buster, surfaced unclassified.
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


_HOST_SUFFIX = ".fontawesome.com"
_HOST_EXACT = "fontawesome.com"


@register
class FontAwesomeModule(TrackerModule):
    """Detect Font Awesome icon-CDN stylesheet / webfont fetches."""

    module_id = "font_awesome"
    module_name = "Font Awesome"
    vendor = "Fonticons, Inc. (Font Awesome)"
    legal_jurisdiction = "US"
    data_residency = "US (Bentonville, AR HQ); Font Awesome global CDN edge"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Icon stylesheet + webfont CDN (like google_fonts / adobe_fonts):
    #   privacy 1.0 (presence leak — IP/UA/Referer, no identifier), security
    #   1.0 (external CSS is style-capable, above static binaries),
    #   resilience 2.0 (US host for a self-hostable cosmetic asset — habit
    #   dependency).
    impact_rating = ImpactRating(privacy=1.0, security=1.0, resilience=2.0)
    impact_notes = {
        "resilience": "A US-controlled host for icons/fonts that are "
            "trivially self-hostable — a dependency of habit.",
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
