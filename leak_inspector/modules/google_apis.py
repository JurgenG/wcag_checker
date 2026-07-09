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

"""Catch-all detector for Google API hosts (``*.googleapis.com``).

``googleapis.com`` fronts dozens of Google services. The *specific* ones
this project recognises have their own modules and win first
(first-match-wins): ``fonts.googleapis.com`` → :mod:`.google_fonts`,
``ajax.`` / ``storage.`` / ``youtube.googleapis.com`` → :mod:`.google_cdn`,
``maps.googleapis.com`` → :mod:`.google_maps`. This module is the
**residual catch-all** for everything else on the domain — observed in
the wild as ``mt.`` (Maps raster tiles / icons), ``places.`` (Maps
Places API), and ``translate.`` / ``translate-pa.`` (the Google
Translate widget and its language API).

Because it is a catch-all it must register **after** the specific Google
modules (see ``__init__.py``); it labels only the parameters it can
defend and falls everything else through to ``CAT_OTHER``. The privacy
event is the fetch itself: visitor IP / ``User-Agent`` / ``Referer`` to
a US controller. The ``key`` field is a *public* per-site Google API
key (config, identical for every visitor), not a visitor identifier.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIX = ".googleapis.com"
_HOST_EXACT = "googleapis.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "key":              (CAT_TECHNICAL, "Public Google API key (per-site config — same for every visitor)", IMPACT_LOW),
    "client":           (CAT_TECHNICAL, "Google API client identifier (e.g. ``te`` for Translate)", IMPACT_LOW),
    "display_language": (CAT_TECHNICAL, "UI / display language code", IMPACT_LOW),
    "hl":               (CAT_TECHNICAL, "Host-language code", IMPACT_LOW),
    "gl":               (CAT_TECHNICAL, "Geo-location country code", IMPACT_LOW),
    "callback":         (CAT_TECHNICAL, "JSONP callback name", IMPACT_LOW),
    "v":                (CAT_TECHNICAL, "Version / cache-bust tag", IMPACT_LOW),
    "_":                (CAT_TECHNICAL, "Cache-busting timestamp", IMPACT_LOW),
}


@register
class GoogleApisModule(TrackerModule):
    """Catch-all detector for residual ``*.googleapis.com`` traffic."""

    module_id = "google_apis"
    module_name = "Google APIs (googleapis.com)"
    vendor = "Google LLC"
    legal_jurisdiction = "US"
    data_residency = "Google global infrastructure"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply; catch-all for googleapis.com requests not claimed by a more specific module (Fonts / Maps / CDN)"
    # Residual catch-all, sibling of google_misc (the google.com catch-all)
    #   — rated at the same floor. privacy 1.0: an unattributed
    #   googleapis.com fetch (map tiles, a translate asset, an API lookup)
    #   discloses presence-of-visit to a US controller, no named visitor
    #   payload (rubric privacy 1.0). security 2.0: can return executable
    #   Google JS (e.g. the Translate widget loader) into the origin,
    #   unpinned but narrow (rubric 2.0). resilience 2.0: US controller for
    #   a non-load-bearing function (rubric 2.0).
    impact_rating = ImpactRating(privacy=1.0, security=2.0, resilience=2.0)
    impact_notes = {
        "security": "Residual googleapis.com resources can include "
            "executable Google JavaScript (e.g. the Translate widget) "
            "running in your origin.",
        "resilience": "A US-controlled dependency for a non-load-bearing "
            "function (maps, translation, API lookups).",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Google API parameter", IMPACT_LOW)
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
