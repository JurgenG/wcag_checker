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

"""Google static asset CDN (gstatic.com) detector.

``*.gstatic.com`` is Google's general-purpose static-asset CDN. Several
specific Google products carve out their own sub-domains
(``fonts.gstatic.com`` for Google Fonts, ``maps.gstatic.com`` for Google
Maps) — those are already claimed by the dedicated modules and, since
``detect()`` is first-match-wins and gstatic sorts *after* ``google_*``
in alphabetical registration order, they win automatically.

What's left for this module is the residual:

* ``www.gstatic.com`` — site icons, YouTube player widgets, sign-in
  assets, doodles, generic Google-product chrome.
* ``csi.gstatic.com`` — Client-Side Instrumentation beacon (Google
  internal speed/error reporting).
* ``ssl.gstatic.com`` — legacy SSL asset host.

Why it matters even though it's "just images and JS": every request
leaks visitor IP + ``User-Agent`` + ``Referer`` to Google, and the
specific filename can act as a feature-fingerprint (e.g. which YouTube
control icons were requested narrows the embedded-player variant).

There are no analytics parameters here; URLs are path-based.
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


_HOST_SUFFIX = ".gstatic.com"
_HOST_EXACT = "gstatic.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "ver":  (CAT_TECHNICAL, "Asset version tag",            IMPACT_LOW),
    "v":    (CAT_TECHNICAL, "Asset version (short form)",   IMPACT_LOW),
    "hl":   (CAT_TECHNICAL, "Host language",                IMPACT_LOW),
    "_":    (CAT_TECHNICAL, "Cache-busting timestamp",      IMPACT_LOW),
    "kid":  (CAT_TECHNICAL, "Key identifier (signed asset)", IMPACT_LOW),
}


@register
class GStaticModule(TrackerModule):
    """Detect residual Google static-asset CDN traffic (post-Fonts / post-Maps)."""

    module_id = "gstatic"
    module_name = "Google static CDN (gstatic)"
    vendor = "Google LLC"
    legal_jurisdiction = "US"
    data_residency = "Google global CDN"
    sovereignty_notes = "US CLOUD Act applies; every asset fetch leaks visitor IP + UA + Referer to Google. fonts.gstatic.com and maps.gstatic.com are claimed by the dedicated modules and do not surface here"
    # privacy 1.0: presence-of-visit leak to a US controller, no
    #   identifier (rubric privacy 1.0). security 2.0: the residual here
    #   includes executable widget/sign-in JS (e.g. www.gstatic.com player
    #   chrome) running unpinned in the origin, narrow surface (rubric
    #   2.0); above pure static (0.5). resilience 2.0: US controller,
    #   cosmetic/replaceable asset host (rubric 2.0).
    impact_rating = ImpactRating(privacy=1.0, security=2.0, resilience=2.0)
    impact_notes = {
        "security": "Serves widget / sign-in JavaScript into your origin "
            "unpinned — narrower than a bucket host, but still executable "
            "code from Google.",
        "resilience": "A US-controlled asset host for replaceable "
            "chrome.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized gstatic parameter", IMPACT_LOW)
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
