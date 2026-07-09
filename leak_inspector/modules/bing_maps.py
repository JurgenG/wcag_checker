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

"""Bing Maps detector.

Microsoft Bing Maps tile + REST API. Same product class as Google Maps:
every tile and geocode call leaks visitor IP + ``User-Agent`` +
``Referer`` to Microsoft, and search / location queries reveal what the
visitor is looking up.

Recognized hosts:

* ``dev.virtualearth.net`` — primary REST API
* ``*.virtualearth.net`` — tile servers (``t0.tiles.virtualearth.net``,
  ``ecn.t0.tiles.virtualearth.net`` …) and ancillary endpoints
* ``*.tiles.virtualearth.net`` — explicit tile suffix
* ``www.bing.com/maps/...`` is *not* claimed here — the bing.com host
  serves many non-maps things; if a capture surfaces Bing Maps via
  bing.com we'd extend specifically.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIX = ".virtualearth.net"
_HOST_EXACT = "virtualearth.net"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "key":         (CAT_TECHNICAL,  "Bing Maps API key (per-customer)",         IMPACT_LOW),
    "AuthKey":     (CAT_TECHNICAL,  "Bing Maps Auth key (alt form)",            IMPACT_LOW),
    "session":     (CAT_IDENTIFIER, "Maps session ID (charged-session billing)", IMPACT_MEDIUM),
    "query":       (CAT_CONTENT, "Geocode / Locations API query",               IMPACT_MEDIUM),
    "q":           (CAT_CONTENT, "Search query (short form)",                   IMPACT_MEDIUM),
    "addressLine": (CAT_CONTENT, "Structured search: street address",           IMPACT_MEDIUM),
    "locality":    (CAT_CONTENT, "Structured search: locality / city",          IMPACT_MEDIUM),
    "adminDistrict": (CAT_CONTENT, "Structured search: state / region",        IMPACT_LOW),
    "postalCode":  (CAT_CONTENT, "Structured search: postal code",              IMPACT_LOW),
    "countryRegion": (CAT_CONTENT, "Structured search: country",                IMPACT_LOW),
    "point":       (CAT_CONTENT, "Reverse-geocode lat,lng",                     IMPACT_MEDIUM),
    "centerPoint": (CAT_CONTENT, "Map viewport center lat,lng",                 IMPACT_MEDIUM),
    "mapArea":     (CAT_CONTENT, "Map viewport bounding box",                   IMPACT_MEDIUM),
    "userMapView": (CAT_CONTENT, "Visitor's current map view (bbox)",           IMPACT_MEDIUM),
    "userLocation": (CAT_CONTENT, "Visitor's reported location",                IMPACT_MEDIUM),
    "wp":          (CAT_CONTENT, "Directions waypoint list",                    IMPACT_MEDIUM),
    "destinations": (CAT_CONTENT, "Distance-matrix destinations",               IMPACT_MEDIUM),
    "origins":     (CAT_CONTENT, "Distance-matrix origins",                     IMPACT_MEDIUM),
    "o":           (CAT_TECHNICAL, "Output format (json / xml)",                IMPACT_LOW),
    "output":      (CAT_TECHNICAL, "Output format (alt form)",                  IMPACT_LOW),
    "c":           (CAT_TECHNICAL, "Culture / language code",                   IMPACT_LOW),
    "ur":          (CAT_TECHNICAL, "User region hint",                          IMPACT_LOW),
    "lvl":         (CAT_TECHNICAL, "Zoom level",                                IMPACT_LOW),
    "mapSize":     (CAT_TECHNICAL, "Static-map dimensions",                     IMPACT_LOW),
    "mapVersion":  (CAT_TECHNICAL, "Map style version",                         IMPACT_LOW),
    "version":     (CAT_TECHNICAL, "API version",                               IMPACT_LOW),
    "includeNeighborhood": (CAT_TECHNICAL, "Include-neighborhood flag",        IMPACT_LOW),
    "maxResults":  (CAT_TECHNICAL, "Result limit",                              IMPACT_LOW),
    "jsonp":       (CAT_TECHNICAL, "JSONP callback name",                       IMPACT_LOW),
    "callback":    (CAT_TECHNICAL, "JSONP callback name (alt form)",            IMPACT_LOW),
}


@register
class BingMapsModule(TrackerModule):
    """Detect Bing Maps tile / REST / Locations API traffic."""

    module_id = "bing_maps"
    module_name = "Bing Maps"
    vendor = "Microsoft Corporation"
    legal_jurisdiction = "US"
    data_residency = "Microsoft Azure global infrastructure"
    sovereignty_notes = "US CLOUD Act applies; every tile + geocode leaks visitor IP + UA + Referer to Microsoft"
    # Maps: privacy 1.5 (lookup content, session-tied), security 2.0 (JS
    #   API in origin), resilience 2.5 (US Microsoft, replaceable). Same
    #   shape as google_maps / apple_maps.
    impact_rating = ImpactRating(privacy=1.5, security=2.0, resilience=2.5)
    impact_notes = {
        "privacy": "What the visitor looked up (search terms, "
            "coordinates) travels to Microsoft with each tile and "
            "geocode.",
        "security": "The Maps JavaScript API runs in your page origin, "
            "unpinned.",
        "resilience": "An embedded-maps dependency on a US vendor.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Bing Maps parameter", IMPACT_LOW)
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
