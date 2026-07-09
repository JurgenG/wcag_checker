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

"""Apple Maps (MapKit JS) detector.

Apple Maps's web embed product, MapKit JS. Smaller per-page footprint
than Google / Bing Maps, and Apple's stated privacy posture is stronger
(ephemeral identifiers, on-device processing of search bias), but every
tile + search request still leaks visitor IP + ``User-Agent`` +
``Referer`` to Apple.

Recognized hosts:

* ``maps.apple.com`` — the public "open in Apple Maps" redirector
* ``*.apple-mapkit.com`` — MapKit JS asset + tile CDN
  (``cdn.apple-mapkit.com``, ``cdn4.apple-mapkit.com``, etc.)
* ``gsp10-ssl.apple.com``, ``gsp64-ssl.ls.apple.com``,
  ``gspe19-ssl.ls.apple.com`` — Apple Maps service endpoints (GSPE =
  Geo Services Performance Endpoint family); only the explicit
  ``ls.apple.com`` / ``gsp*-ssl.apple.com`` patterns are claimed, not
  the broader ``apple.com`` (which serves the marketing site).
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


_HOST_SUFFIX_MAPKIT = ".apple-mapkit.com"
_HOST_EXACT_MAPKIT = "apple-mapkit.com"
_HOST_SUFFIX_LS = ".ls.apple.com"
_HOST_PREFIXES_GSP: tuple[str, ...] = ("gsp10-ssl.", "gsp64-ssl.", "gsp19-ssl.", "gspe19-ssl.")
_HOST_EXACT_MAPS_APPLE = "maps.apple.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "token":          (CAT_TECHNICAL, "MapKit JS JWT token (per-customer Apple-issued)", IMPACT_LOW),
    "team":           (CAT_TECHNICAL, "Apple Developer team identifier",       IMPACT_LOW),
    "useBundleId":    (CAT_TECHNICAL, "Bundle-ID auth flag",                    IMPACT_LOW),
    "q":              (CAT_CONTENT, "Search query (place / address text)",      IMPACT_MEDIUM),
    "query":          (CAT_CONTENT, "Search query (alt form)",                  IMPACT_MEDIUM),
    "address":        (CAT_CONTENT, "Geocode address",                          IMPACT_MEDIUM),
    "ll":             (CAT_CONTENT, "Map center lat,lng",                       IMPACT_MEDIUM),
    "coordinate":     (CAT_CONTENT, "Reverse-geocode coordinate",               IMPACT_MEDIUM),
    "near":           (CAT_CONTENT, "Search-bias center coordinate",            IMPACT_MEDIUM),
    "searchLocation": (CAT_CONTENT, "Search-bias coordinate (MapKit JS)",       IMPACT_MEDIUM),
    "searchRegion":   (CAT_CONTENT, "Search-bias region",                       IMPACT_MEDIUM),
    "userLocation":   (CAT_CONTENT, "Visitor's reported location",              IMPACT_MEDIUM),
    "origin":         (CAT_CONTENT, "Directions origin",                        IMPACT_MEDIUM),
    "destination":    (CAT_CONTENT, "Directions destination",                   IMPACT_MEDIUM),
    "saddr":          (CAT_CONTENT, "Source address (maps.apple.com redirect)", IMPACT_MEDIUM),
    "daddr":          (CAT_CONTENT, "Destination address (maps.apple.com redirect)", IMPACT_MEDIUM),
    "z":              (CAT_TECHNICAL, "Zoom level",                             IMPACT_LOW),
    "t":              (CAT_TECHNICAL, "Map type (m / k / h)",                   IMPACT_LOW),
    "spn":            (CAT_TECHNICAL, "Map span (degrees)",                     IMPACT_LOW),
    "language":       (CAT_TECHNICAL, "UI / response language",                 IMPACT_LOW),
    "lang":           (CAT_TECHNICAL, "Language code (alt form)",               IMPACT_LOW),
    "v":              (CAT_TECHNICAL, "MapKit JS version",                      IMPACT_LOW),
    "version":        (CAT_TECHNICAL, "API version (alt form)",                 IMPACT_LOW),
    "callback":       (CAT_TECHNICAL, "JSONP callback name",                    IMPACT_LOW),
    "result-type":    (CAT_TECHNICAL, "Search result-type filter",              IMPACT_LOW),
    "limitToCountries": (CAT_TECHNICAL, "Country restriction for results",      IMPACT_LOW),
}


@register
class AppleMapsModule(TrackerModule):
    """Detect Apple Maps + MapKit JS asset / tile / search traffic."""

    module_id = "apple_maps"
    module_name = "Apple Maps / MapKit JS"
    vendor = "Apple Inc."
    legal_jurisdiction = "US"
    data_residency = "Apple global infrastructure"
    sovereignty_notes = "US CLOUD Act applies; Apple's stated privacy posture is stronger than Google/Bing but tile + geocode requests still leak IP + UA + Referer"
    # Maps: privacy 1.5 (tile/geocode carries what the visitor looks up,
    #   session-tied; rubric 1.5, as google_maps). security 2.0 (MapKit JS
    #   unpinned in origin). resilience 2.5 (US, replaceable supporting
    #   feature — rubric 2.5).
    impact_rating = ImpactRating(privacy=1.5, security=2.0, resilience=2.5)
    impact_notes = {
        "privacy": "What the visitor looked up (search terms, "
            "coordinates) travels to Apple with each tile and geocode.",
        "security": "The MapKit JS API runs in your page origin, "
            "unpinned.",
        "resilience": "An embedded-maps dependency on a US vendor.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host == _HOST_EXACT_MAPS_APPLE:
            return True
        if host == _HOST_EXACT_MAPKIT or host.endswith(_HOST_SUFFIX_MAPKIT):
            return True
        if host.endswith(_HOST_SUFFIX_LS):
            return True
        if any(host.startswith(prefix) for prefix in _HOST_PREFIXES_GSP):
            return True
        return False

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Apple Maps parameter", IMPACT_LOW)
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
