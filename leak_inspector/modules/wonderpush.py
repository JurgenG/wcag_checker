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

"""WonderPush web-push-notification detector.

WonderPush (Paris, France — EU) is a web/mobile push-notification
platform. The browser SDK loads from ``cdn.by.wonderpush.com``
(``/sdk/<ver>/wonderpush.min.js`` + ``/config/webkeys/<id>`` config) and
reports engagement to ``measurements-api.wonderpush.com/v1/events``. To
deliver push it registers a service worker and a persistent push
subscription, building a per-subscriber engagement profile.

Recognized hosts: any subdomain of ``wonderpush.com``. Event payloads
travel in request bodies v1.0 capture does not record.
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


_HOST_SUFFIX = ".wonderpush.com"
_HOST_EXACT = "wonderpush.com"


@register
class WonderPushModule(TrackerModule):
    """Detect WonderPush web-push-notification SDK traffic."""

    module_id = "wonderpush"
    module_name = "WonderPush"
    vendor = "WonderPush"
    legal_jurisdiction = "FR"
    data_residency = "EU (France); GDPR-compliant push platform"
    sovereignty_notes = "EU-controlled (France) — GDPR-native, no Schrems II concern"
    # Web-push platform (EU): privacy 2.5 (a persistent push subscription +
    #   /v1/events engagement telemetry builds a per-subscriber profile —
    #   contained EU vendor, not cross-site ad tracking), security 2.5 (an
    #   unpinned SDK + a service worker run in your origin), resilience 1.0
    #   (EU vendor, GDPR-native).
    impact_rating = ImpactRating(privacy=2.5, security=2.5, resilience=1.0)
    impact_notes = {
        "privacy": "A persistent push subscription plus engagement "
            "telemetry build a per-subscriber profile at a contained EU "
            "vendor — not cross-site ad tracking.",
        "security": "Loads an unpinned SDK and registers a service worker "
            "in your origin.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            params.append(
                ParamInfo(
                    key=key, value=value, category=CAT_OTHER,
                    meaning="WonderPush parameter — unclassified",
                    privacy_impact=IMPACT_LOW, event_index=event.event_id,
                )
            )
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
