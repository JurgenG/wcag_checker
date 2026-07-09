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

"""jsDelivr open-source CDN detector.

jsDelivr is the dominant free CDN for npm / GitHub / WordPress assets.
URLs are path-based (``/npm/<package>@<version>/<file>``) and rarely
carry query parameters — so per-request privacy exposure is limited to
IP + ``User-Agent`` + ``Referer`` reaching whichever CDN edge serves
the request.

Sovereignty footnote: the jsDelivr *project* is operated by the
Prosperous Net Foundation (a Czech-registered non-profit). The actual
edge servers are run by sponsoring CDN providers — primarily Cloudflare
(US), Fastly (US), and Bunny.net (SI). For any given request, the
visitor's IP is exposed to the *serving* edge, not to a single
controller. We list legal jurisdiction as CZ for the operator and flag
the multi-CDN reality in the notes.

Recognized hosts:

* ``cdn.jsdelivr.net`` — primary asset host
* ``data.jsdelivr.com`` — package metadata API
* ``www.jsdelivr.com`` — project site
* ``*.jsdelivr.net`` / ``*.jsdelivr.com`` — catch-all for ancillary
  endpoints
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


_HOST_SUFFIXES: tuple[str, ...] = (".jsdelivr.net", ".jsdelivr.com")
_HOST_EXACTS: frozenset[str] = frozenset({"jsdelivr.net", "jsdelivr.com"})


_PARAMS: dict[str, tuple[str, str, str]] = {
    "v":         (CAT_TECHNICAL, "Cache-bust version tag",                 IMPACT_LOW),
    "_":         (CAT_TECHNICAL, "Cache-busting timestamp",                IMPACT_LOW),
    "callback":  (CAT_TECHNICAL, "JSONP callback name (data API)",         IMPACT_LOW),
    "limit":     (CAT_TECHNICAL, "Metadata API result limit",              IMPACT_LOW),
    "structure": (CAT_TECHNICAL, "Metadata API response structure",        IMPACT_LOW),
}


@register
class JsDelivrModule(TrackerModule):
    """Detect jsDelivr open-source CDN traffic."""

    module_id = "jsdelivr"
    module_name = "jsDelivr"
    vendor = "Prosperous Net Foundation (jsDelivr)"
    legal_jurisdiction = "CZ"
    data_residency = "Multi-CDN: Cloudflare (US) + Fastly (US) + Bunny.net (SI), routed by region"
    sovereignty_notes = "Open-source project operated from CZ but edge servers belong to US/SI CDN sponsors — the serving edge sees visitor IP, not jsDelivr itself"
    # Asset CDN serving JS libraries: privacy 1.0 (presence-of-visit leak
    #   to the serving edge), security 2.5 (executable JS into the origin,
    #   unpinned — the supply-chain surface), resilience 1.0 (the project
    #   is EU/CZ-operated and trivially replaceable/self-hostable, though
    #   the edge is US/SI — rubric 1.0 independent EU third party).
    impact_rating = ImpactRating(privacy=1.0, security=2.5, resilience=1.0)
    impact_notes = {
        "security": "Serves JavaScript libraries into your origin "
            "unpinned — a CDN compromise would run as your site.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _HOST_EXACTS:
            return True
        return any(host.endswith(suffix) for suffix in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized jsDelivr parameter", IMPACT_LOW)
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
