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

"""Google Maps detector.

Google Maps tile / API / Street View traffic. Even though Maps isn't
an "analytics" product, every tile and API request:

* leaks the visitor's IP, ``User-Agent``, and ``Referer`` to Google;
* often carries a search query (``q=…``), an explicit ``latlng=…``, or
  an ``address=…`` parameter — revealing what the visitor is looking
  up;
* is tied to the operator's API key (``key=…``) — which links the
  request back to a specific Google Cloud account.

Recognized hosts:

* ``maps.googleapis.com`` — primary Maps Platform JS / REST API
* ``maps.gstatic.com`` — tiles / icons / static images
* ``maps.google.com`` — older Maps endpoints
* ``mts0.google.com`` / ``mts1.google.com`` — map-tile servers
* ``khms0.google.com`` / ``khms1.google.com`` — satellite-imagery tiles
* ``*.googleapis.com`` is *not* matched broadly — that hostname hosts
  many non-Maps services. Only the exact Maps hosts above are claimed.
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


_HOST_EXACT: frozenset[str] = frozenset({
    "maps.googleapis.com",
    "maps.gstatic.com",
    "maps.google.com",
    "mts0.google.com",
    "mts1.google.com",
    "khms0.google.com",
    "khms1.google.com",
})


_PARAMS: dict[str, tuple[str, str, str]] = {
    "key":      (CAT_TECHNICAL,  "Google Maps Platform API key (per-customer)",  IMPACT_LOW),
    "client":   (CAT_TECHNICAL,  "Maps for Business client ID (per-customer, legacy)", IMPACT_LOW),
    "channel":  (CAT_TECHNICAL,  "Customer-supplied channel attribution string", IMPACT_LOW),
    "signature": (CAT_TECHNICAL, "URL HMAC signature (signed Maps API requests)", IMPACT_LOW),
    "q":        (CAT_CONTENT, "Geocode / search query (free-text place lookup)", IMPACT_MEDIUM),
    "address":  (CAT_CONTENT, "Geocode address",                                IMPACT_MEDIUM),
    "latlng":   (CAT_CONTENT, "Reverse-geocode latitude,longitude pair",        IMPACT_MEDIUM),
    "components": (CAT_CONTENT, "Geocode component filter",                     IMPACT_LOW),
    "destination": (CAT_CONTENT, "Directions destination",                      IMPACT_MEDIUM),
    "origin":   (CAT_CONTENT, "Directions origin",                              IMPACT_MEDIUM),
    "waypoints": (CAT_CONTENT, "Directions waypoints",                          IMPACT_MEDIUM),
    "location": (CAT_CONTENT, "Places nearby-search center location",           IMPACT_MEDIUM),
    "radius":   (CAT_TECHNICAL, "Places search radius",                         IMPACT_LOW),
    "place_id": (CAT_TECHNICAL, "Place reference identifier",                   IMPACT_LOW),
    "pano":     (CAT_CONTENT, "Street View panorama identifier",                IMPACT_MEDIUM),
    "panoid":   (CAT_CONTENT, "Street View panorama ID (alt form)",             IMPACT_MEDIUM),
    "fov":      (CAT_TECHNICAL, "Street View field-of-view",                    IMPACT_LOW),
    "heading":  (CAT_TECHNICAL, "Street View heading",                          IMPACT_LOW),
    "pitch":    (CAT_TECHNICAL, "Street View pitch",                            IMPACT_LOW),
    "v":        (CAT_TECHNICAL, "Maps JS API version",                          IMPACT_LOW),
    "libraries": (CAT_TECHNICAL, "Requested JS API libraries (places / drawing / …)", IMPACT_LOW),
    "language": (CAT_TECHNICAL, "UI / response language",                       IMPACT_LOW),
    "region":   (CAT_TECHNICAL, "Region-bias hint",                             IMPACT_LOW),
    "format":   (CAT_TECHNICAL, "Response format",                              IMPACT_LOW),
    "callback": (CAT_TECHNICAL, "JSONP callback name",                          IMPACT_LOW),
    "sensor":   (CAT_TECHNICAL, "Sensor flag (legacy)",                         IMPACT_LOW),
    "size":     (CAT_TECHNICAL, "Static-map image dimensions",                  IMPACT_LOW),
    "zoom":     (CAT_TECHNICAL, "Tile zoom level",                              IMPACT_LOW),
    "scale":    (CAT_TECHNICAL, "High-DPI scale factor",                        IMPACT_LOW),
    "maptype":  (CAT_TECHNICAL, "Map type (roadmap / satellite / hybrid)",      IMPACT_LOW),
    "markers":  (CAT_CONTENT,   "Static-map markers (lat,lng list)",            IMPACT_MEDIUM),
    "path":     (CAT_CONTENT,   "Static-map path (lat,lng list)",               IMPACT_MEDIUM),
    "style":    (CAT_TECHNICAL, "Static-map style overrides",                   IMPACT_LOW),
    "cb_client": (CAT_TECHNICAL, "Callback client identifier",                  IMPACT_LOW),
}


@register
class GoogleMapsModule(TrackerModule):
    """Detect Google Maps Platform tile / API / Street View traffic."""

    module_id = "google_maps"
    module_name = "Google Maps"
    vendor = "Google LLC"
    legal_jurisdiction = "US"
    data_residency = "Google global CDN"
    sovereignty_notes = "Schrems II / US CLOUD Act / FISA 702 apply; every tile + geocode leaks visitor IP + UA + Referer to Google"
    # privacy 1.5: beyond the bare fetch, tile/geocode requests carry what
    #   the visitor is looking up (q=/latlng=/address=) — purposeful
    #   content collection tied to the session, no durable visitor ID
    #   (rubric privacy 1.5). security 2.0: the JS API runs unpinned in
    #   the origin, single-purpose hardened vendor surface (rubric 2.0).
    #   resilience 2.5: a supporting feature (embedded maps) replaceable
    #   only with real work, US controller (rubric 2.5).
    impact_rating = ImpactRating(privacy=1.5, security=2.0, resilience=2.5)
    impact_notes = {
        "privacy": "What the visitor looked up (search terms, "
            "coordinates, addresses) travels to Google with each tile "
            "and geocode.",
        "security": "The Maps JavaScript API runs in your page origin, "
            "unpinned.",
        "resilience": "An embedded-maps dependency on a US vendor, "
            "replaceable only with real work.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return event.host.lower() in _HOST_EXACT

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Google Maps parameter", IMPACT_LOW)
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
