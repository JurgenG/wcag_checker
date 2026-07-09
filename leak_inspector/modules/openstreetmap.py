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

"""OpenStreetMap / Nominatim detector.

OSM tile servers and the Nominatim geocoding service. Notable as the
only major map provider in this module set with an EU controller
(OpenStreetMap Foundation, UK; Nominatim infrastructure hosted in
Germany), making it the GDPR-friendlier choice for EU operators
relative to Google / Bing / Apple Maps.

Each tile / geocode request leaks the visitor's IP + ``User-Agent`` +
``Referer`` to the OSM tile cache. Nominatim queries additionally
reveal what addresses or places the visitor is searching for.

Recognized hosts:

* ``tile.openstreetmap.org`` (+ ``a.``/``b.``/``c.`` regional mirrors)
* ``nominatim.openstreetmap.org`` — geocoding / reverse-geocoding API
* ``*.openstreetmap.org`` — catch-all for related OSMF endpoints
* ``routing.openstreetmap.de`` — community routing service (DE-hosted)
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_CONTENT,
    CAT_OTHER,
    CAT_PII,
    CAT_TECHNICAL,
    Hit,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIX_OSM = ".openstreetmap.org"
_HOST_EXACT_OSM = "openstreetmap.org"
_HOST_SUFFIX_OSM_DE = ".openstreetmap.de"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "q":             (CAT_CONTENT, "Nominatim search query (place / address text)", IMPACT_MEDIUM),
    "street":        (CAT_CONTENT, "Structured search: street",                IMPACT_MEDIUM),
    "city":          (CAT_CONTENT, "Structured search: city",                  IMPACT_MEDIUM),
    "county":        (CAT_CONTENT, "Structured search: county",                IMPACT_LOW),
    "state":         (CAT_CONTENT, "Structured search: state",                 IMPACT_LOW),
    "country":       (CAT_CONTENT, "Structured search: country",               IMPACT_LOW),
    "postalcode":    (CAT_CONTENT, "Structured search: postcode",              IMPACT_LOW),
    "lat":           (CAT_CONTENT, "Reverse-geocode latitude",                 IMPACT_MEDIUM),
    "lon":           (CAT_CONTENT, "Reverse-geocode longitude",                IMPACT_MEDIUM),
    "viewbox":       (CAT_CONTENT, "Map viewport bounding box",                IMPACT_MEDIUM),
    "bounded":       (CAT_TECHNICAL, "Bounded-search flag",                    IMPACT_LOW),
    "email":         (CAT_PII, "Caller email (Nominatim usage-policy header)", IMPACT_HIGH),
    "osm_type":      (CAT_TECHNICAL, "OSM entity type (node / way / relation)", IMPACT_LOW),
    "osm_id":        (CAT_TECHNICAL, "OSM entity ID",                          IMPACT_LOW),
    "place_id":      (CAT_TECHNICAL, "Nominatim place ID",                     IMPACT_LOW),
    "format":        (CAT_TECHNICAL, "Response format (json / xml / geojson)",  IMPACT_LOW),
    "addressdetails": (CAT_TECHNICAL, "Include-address-details flag",          IMPACT_LOW),
    "namedetails":   (CAT_TECHNICAL, "Include-name-details flag",              IMPACT_LOW),
    "extratags":     (CAT_TECHNICAL, "Include-extra-tags flag",                IMPACT_LOW),
    "polygon_geojson": (CAT_TECHNICAL, "Polygon-geojson output flag",          IMPACT_LOW),
    "limit":         (CAT_TECHNICAL, "Result limit",                           IMPACT_LOW),
    "dedupe":        (CAT_TECHNICAL, "Deduplicate-results flag",               IMPACT_LOW),
    "accept-language": (CAT_TECHNICAL, "Accept-Language hint",                 IMPACT_LOW),
    "zoom":          (CAT_TECHNICAL, "Reverse-geocode zoom level",             IMPACT_LOW),
}


@register
class OpenStreetMapModule(TrackerModule):
    """Detect OpenStreetMap tile + Nominatim geocoding traffic."""

    module_id = "openstreetmap"
    module_name = "OpenStreetMap / Nominatim"
    vendor = "OpenStreetMap Foundation (Nominatim hosting in Germany)"
    legal_jurisdiction = "UK"
    data_residency = "UK / EU (volunteer-operated; Nominatim primary hosting in Germany)"
    sovereignty_notes = "Non-commercial community operator; no first-class user-tracking model"
    # The open / sovereign maps alternative, deliberately rated below the
    # commercial maps (google/apple/bing): privacy 1.5 (geocode lookup
    #   content, session-tied), security 1.0 (tiles are images + a geocode
    #   API, no heavy JS API in the origin — rubric 1.0), resilience 1.5
    #   (UK foundation, Nominatim hosted in Germany, non-profit, trivially
    #   self-hostable — non-EU adequacy / EU-hosted, rubric 1.5).
    impact_rating = ImpactRating(privacy=1.5, security=1.0, resilience=1.5)
    impact_notes = {
        "privacy": "Geocode lookups carry what the visitor searched, "
            "tied to the session.",
        "resilience": "The open / non-profit maps option (Nominatim "
            "hosted in Germany), trivially self-hostable — rated below "
            "the commercial map vendors.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host == _HOST_EXACT_OSM or host.endswith(_HOST_SUFFIX_OSM):
            return True
        if host.endswith(_HOST_SUFFIX_OSM_DE):
            return True
        return False

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized OSM / Nominatim parameter", IMPACT_LOW)
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
