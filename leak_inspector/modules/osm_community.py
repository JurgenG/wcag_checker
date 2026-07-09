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

"""European OpenStreetMap community tile-server detector.

The OpenStreetMap national chapters run their own public raster-tile
servers — the sovereign, EU-hosted maps alternative to the commercial
vendors (Google / Bing / Apple / Mapbox). This module recognises the
common EU community tile hosts:

* ``osm.be`` — **OpenStreetMap Belgium** (e.g. ``tile.osm.be``, the
  localized ``osmbe-nl`` / ``osmbe-fr`` styles). Observed in the wild.
* ``openstreetmap.fr`` — **OpenStreetMap France** (e.g.
  ``tile.openstreetmap.fr`` / ``a.``/``b.``/``c.`` mirrors), one of the
  most widely-used alternative OSM tile sources (the OSM-FR + HOT styles).

It is deliberately **disjoint** from :mod:`.openstreetmap`, which owns
the OpenStreetMap Foundation hosts (``openstreetmap.org``) and the
German community service (``openstreetmap.de``); those keep their own
module under first-match-wins. New EU chapter tile hosts can be added to
the suffix list as captures surface them — only documented community
servers, never guessed.

These hosts serve only map-tile images — no executable JavaScript, no
tracking parameters. The privacy event is the tile fetch itself
(visitor IP + the map area viewed, disclosed to an EU non-profit).
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


#: EU OpenStreetMap community chapter tile domains. Matched as exact
#: hosts and as suffixes (so ``tile.``, ``a.tile.``, … all resolve).
#: Excludes the OSMF ``.org`` / German ``.de`` hosts — those belong to
#: :mod:`.openstreetmap`.
_HOST_SUFFIXES: tuple[str, ...] = (".osm.be", ".openstreetmap.fr")
_HOST_EXACTS: frozenset[str] = frozenset({"osm.be", "openstreetmap.fr"})


@register
class OpenStreetMapCommunityModule(TrackerModule):
    """Detect EU OpenStreetMap community tile servers (BE, FR, …)."""

    module_id = "osm_community"
    module_name = "OpenStreetMap community tiles (EU)"
    vendor = "OpenStreetMap regional chapters (community)"
    legal_jurisdiction = "EU"
    data_residency = "EU; OpenStreetMap national-chapter community infrastructure (Belgium, France, …)"
    sovereignty_notes = "EU / GDPR-bound; non-profit community chapters, not a foreign controller"
    # Sovereign EU map-tile hosts: privacy 1.0 (tile fetch reveals viewport
    #   + IP to an EU non-profit — the floor for a maps host, below the
    #   OSMF .org module's 1.5 which also runs geocoding). security 0.5
    #   (serve only PNG tiles — no executable surface). resilience 1.0
    #   (EU community services — the encouraged, sovereign maps posture).
    impact_rating = ImpactRating(privacy=1.0, security=0.5, resilience=1.0)

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host in _HOST_EXACTS or any(
            host.endswith(s) for s in _HOST_SUFFIXES
        )

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = [
            ParamInfo(
                key=key,
                value=value,
                category=CAT_OTHER,
                meaning="Tile-fetch URL parameter (not a tracking field)",
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
