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

"""Mapbox detector.

Mapbox, Inc. (US) is a commercial maps / geocoding platform — the
same product class as Google / Bing / Apple Maps. Every tile, style
and geocode request on ``api.mapbox.com`` leaks the visitor's IP,
``User-Agent`` and ``Referer``, carries the operator's ``access_token``
(tying the request to a Mapbox account), and — for geocoding — reveals
what the visitor searched for. Mapbox also runs a telemetry endpoint
(``events.mapbox.com``) that collects map-interaction events.

Recognized hosts: ``api.mapbox.com`` (GL JS / styles / geocoding /
tiles), ``events.mapbox.com`` (telemetry), and other ``*.mapbox.com``
serving hosts (``a./b.tiles.mapbox.com``).
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_CONTENT,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIX = ".mapbox.com"
_HOST_EXACT = "mapbox.com"


# key -> (category, meaning, impact)
_PARAMS: dict[str, tuple[str, str, str]] = {
    "access_token": (CAT_TECHNICAL, "Mapbox access token (the operator's account key)", IMPACT_LOW),
    "q":            (CAT_CONTENT,   "Geocoding search query — what the visitor looked up", IMPACT_MEDIUM),
    "proximity":    (CAT_CONTENT,   "Geocoding proximity bias (coordinates)", IMPACT_MEDIUM),
    "bbox":         (CAT_CONTENT,   "Bounding box for the query", IMPACT_LOW),
    "types":        (CAT_TECHNICAL, "Geocoding result-type filter", IMPACT_LOW),
    "language":     (CAT_TECHNICAL, "Requested language", IMPACT_LOW),
    "limit":        (CAT_TECHNICAL, "Result limit", IMPACT_LOW),
}


@register
class MapboxModule(TrackerModule):
    """Detect Mapbox maps / geocoding / telemetry traffic."""

    module_id = "mapbox"
    module_name = "Mapbox"
    vendor = "Mapbox, Inc."
    legal_jurisdiction = "US"
    data_residency = "US (Washington, DC HQ); Mapbox global serving infrastructure"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Embedded commercial maps (like google_maps / bing_maps / apple_maps):
    #   privacy 1.5 (geocode lookups carry the visitor's search terms /
    #   coordinates), security 2.0 (the Maps GL JS runs in the page origin,
    #   unpinned), resilience 2.5 (an embedded-maps dependency on a US
    #   vendor).
    impact_rating = ImpactRating(privacy=1.5, security=2.0, resilience=2.5)
    impact_notes = {
        "privacy": "What the visitor looked up (search terms, coordinates) "
            "travels to Mapbox with each geocode, plus map-interaction "
            "telemetry to events.mapbox.com.",
        "security": "The Mapbox GL JavaScript runs in your page origin, "
            "unpinned.",
        "resilience": "An embedded-maps dependency on a US vendor, "
            "replaceable only with real work.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Mapbox parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key, value=value, category=category, meaning=meaning,
                    privacy_impact=impact, event_index=event.event_id,
                )
            )
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
