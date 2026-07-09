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

"""Nativo (formerly PostRelease) native-advertising detector.

Nativo, Inc. (El Segundo, CA, US; formerly PostRelease) runs a native-
advertising platform. Its ad-serving / tracking traffic rides on
``jadserve.postrelease.com`` (``/t?ntv_kv=<key-values>&ntv_url=<page
URL>``) — the same content-recommendation / native-ad class as Taboola
/ Outbrain: a native unit plus a tracking beacon that carries the
visited page URL.

Recognized host: any subdomain of ``postrelease.com``.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
    CAT_CONTENT,
    CAT_OTHER,
    Hit,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIX = ".postrelease.com"
_HOST_EXACT = "postrelease.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "ntv_url": (CAT_CONTENT,    "Page URL the native unit fired on", IMPACT_MEDIUM),
    "ntv_kv":  (CAT_BEHAVIORAL, "Native key-value targeting data", IMPACT_LOW),
}


@register
class NativoModule(TrackerModule):
    """Detect Nativo (PostRelease) native-ad serving / tracking traffic."""

    module_id = "nativo"
    module_name = "Nativo"
    vendor = "Nativo, Inc."
    legal_jurisdiction = "US"
    data_residency = "US (El Segundo, CA HQ); global serving infrastructure"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Native-advertising platform (like Outbrain): privacy 4.0
    #   (native-ad tracking joins the visit to an ad/content profile —
    #   cross-site by design), security 2.5 (ordinary native pixel/loader,
    #   not an OpenRTB sync hub), resilience 2.5 (US, replaceable supporting
    #   content/outreach channel).
    impact_rating = ImpactRating(privacy=4.0, security=2.5, resilience=2.5)
    impact_notes = {
        "privacy": "Native-ad serving + tracking that joins the visit to "
            "an ad/content profile — cross-site by design.",
        "security": "Loads an unpinned Nativo native-ad pixel into your "
            "origin.",
        "resilience": "A US content/outreach vendor — replaceable "
            "supporting feature.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Nativo parameter", IMPACT_LOW)
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
