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

"""App360 municipal-platform asset detector.

``app360.be`` is a Belgian platform used by municipalities; municipal
sites pull shared assets and a small config API from ``www.app360.be``
(observed serving Drupal-style image derivatives under
``/sites/default/files/styles/…`` and ``/api/config/…`` endpoints). It
is the operator's own platform supplier rather than a tracker — a
Belgian (EU) third party carrying the operator's own content. The
privacy event is the fetch itself (visitor IP / ``User-Agent`` /
``Referer`` to the platform); the URL parameters are image-styling
tokens, not visitor data.
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


_HOST_SUFFIX = ".app360.be"
_HOST_EXACT = "app360.be"


@register
class App360Module(TrackerModule):
    """Detect App360 (Belgian municipal platform) asset / API fetches."""

    module_id = "app360"
    module_name = "App360"
    vendor = "App360 (Belgian municipal platform)"
    legal_jurisdiction = "EU"
    data_residency = "Belgium (EU); App360 platform"
    sovereignty_notes = "EU / GDPR-bound; the operator's own platform supplier"
    # The operator's own EU platform supplier carrying its content:
    #   privacy 1.0 (presence leak — IP/UA/Referer to the platform, no
    #   tracking payload), security 1.0 (observed serving the operator's
    #   own image assets / config API), resilience 1.0 (a Belgian EU
    #   supplier — sovereign-friendly, but still a third-party dependency).
    impact_rating = ImpactRating(privacy=1.0, security=1.0, resilience=1.0)

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = [
            ParamInfo(
                key=key,
                value=value,
                category=CAT_OTHER,
                meaning="Asset / API URL parameter (not a tracking field)",
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
