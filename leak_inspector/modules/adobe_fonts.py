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

"""Adobe Fonts (Typekit) detector.

Adobe Fonts (still served from the legacy ``typekit.net`` domain
inherited from the pre-acquisition Typekit Inc.) delivers web fonts
to publisher pages. Sister to ``google_fonts.py`` — same privacy
framing: the fetch itself sends visitor IP, ``User-Agent``, and
``Referer`` to Adobe.

Recognized hosts:

* ``p.typekit.net`` — performance / config endpoint that serves the
  per-kit CSS stylesheet.
* ``use.typekit.net`` — the kit-loader entry point.

URL parameters on ``p.typekit.net``:

* ``k`` — kit ID (the publisher's Typekit project identifier).
* ``a`` — Adobe account ID.
* ``f`` — comma-separated list of font IDs being requested.
* ``s`` / ``ht`` / ``app`` — internal flags (kept in the report
  without invented meaning).

On ``use.typekit.net`` the kit ID is the path segment
(``/<kit-id>.css``); there are no useful query parameters.
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


_HOSTS = {"p.typekit.net", "use.typekit.net"}


_PARAMS: dict[str, tuple[str, str, str]] = {
    "k":   (CAT_TECHNICAL,  "Typekit kit ID (publisher's project identifier)",      IMPACT_LOW),
    "a":   (CAT_TECHNICAL,  "Adobe account ID",                                     IMPACT_LOW),
    "f":   (CAT_CONTENT,    "Requested font IDs (comma-separated)",                  IMPACT_LOW),
    "s":   (CAT_TECHNICAL,  "Internal flag (semantics not publicly documented)",     IMPACT_LOW),
    "ht":  (CAT_TECHNICAL,  "Hash-type flag (semantics not publicly documented)",    IMPACT_LOW),
    "app": (CAT_TECHNICAL,  "App / context flag (e.g. ``typekit``)",                  IMPACT_LOW),
    "v":   (CAT_TECHNICAL,  "Loader / SDK version",                                    IMPACT_LOW),
}


@register
class AdobeFontsModule(TrackerModule):
    """Detect Adobe Fonts (Typekit) stylesheet and kit-loader fetches."""

    module_id = "adobe_fonts"
    module_name = "Adobe Fonts (Typekit)"
    vendor = "Adobe Inc."
    legal_jurisdiction = "US"
    data_residency = "US (San Jose, CA HQ); Adobe global CDN edge"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Typekit font/CSS host: privacy 1.0 (presence leak), security 1.0
    #   (serves a stylesheet — style-capable, rubric 1.0, as google_fonts),
    #   resilience 2.0 (US, cosmetic self-hostable asset — rubric 2.0).
    impact_rating = ImpactRating(privacy=1.0, security=1.0, resilience=2.0)
    impact_notes = {
        "resilience": "A US-controlled host (Typekit) for fonts that are "
            "self-hostable — a dependency of habit.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return event.host.lower() in _HOSTS

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Adobe Fonts parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key,
                    value=value,
                    category=category,
                    meaning=meaning,
                    privacy_impact=impact,
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
