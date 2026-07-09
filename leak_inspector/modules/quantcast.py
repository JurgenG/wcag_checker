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

"""Quantcast detector — measurement + DMP + Choice (TCF CMP).

Quantcast operates an audience-measurement platform (``Quantcast
Measure``), a DMP for buyer-side audience activation, and the
Quantcast Choice TCF v2 consent-management platform.

Recognized hosts:

* ``*.quantserve.com`` — measurement pixel + cookie-sync.
* ``*.quantcast.com`` — Choice CMP (``quantcast.mgr.consensu.org``)
  and corporate marketing pages.

Notable paths on ``quantserve.com``:

* ``/pixel/p-<id>.gif`` — measurement pixel; ``p-<id>`` is the
  publisher's Quantcast property identifier.
* ``/cm`` — cookie-match endpoint.
"""

from __future__ import annotations

import re

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
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


_HOST_SUFFIXES = (".quantserve.com", ".quantcast.com")
_HOST_EXACTS = {"quantserve.com", "quantcast.com"}

_PIXEL_PATH_RE = re.compile(r"^/pixel/(p-[A-Za-z0-9_-]+)(?:\.gif)?$")


_PARAMS: dict[str, tuple[str, str, str]] = {
    "pid":     (CAT_TECHNICAL, "Quantcast publisher property ID",             IMPACT_LOW),
    "a":       (CAT_TECHNICAL, "Quantcast account / advertiser identifier",   IMPACT_LOW),
    "event":   (CAT_BEHAVIORAL, "Event name (refresh, conversion, …)",        IMPACT_MEDIUM),
    "labels":  (CAT_BEHAVIORAL, "Audience labels attached to this hit",       IMPACT_MEDIUM),
    "qcvid":   (CAT_IDENTIFIER, "Quantcast visitor pseudonym",                IMPACT_MEDIUM),
    "idmatch": (CAT_TECHNICAL, "ID-match indicator (1 = match attempted)",    IMPACT_LOW),
    "gdpr":         (CAT_CONSENT, "GDPR-applies flag (0/1)",                   IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "IAB TCF consent string",                    IMPACT_LOW),
    "us_privacy":   (CAT_CONSENT, "IAB CCPA US-privacy string",                IMPACT_LOW),
}


@register
class QuantcastModule(TrackerModule):
    """Detect Quantcast measurement pixel, cookie-sync, and Choice CMP traffic."""

    module_id = "quantcast"
    module_name = "Quantcast"
    vendor = "Quantcast Corporation"
    legal_jurisdiction = "US"
    data_residency = "US (San Francisco, CA HQ); global serving infrastructure"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Measurement + DMP + Choice CMP: privacy 4.0 (cross-site audience),
    # security 4.0 (DMP sync chain). resilience 2.5 (US supporting). The
    # CMP role doesn't lower the tracking impact. See appnexus for shape.
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=2.5)
    impact_notes = {
        "privacy": "Audience measurement + DMP that joins this visit to a "
            "web-wide profile — cross-site by design (the CMP role does "
            "not lower the tracking).",
        "security": "A DMP sync chain redirects the visitor into partners "
            "you cannot enumerate.",
        "resilience": "A US measurement/data dependency, replaceable but "
            "foreign-controlled.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _HOST_EXACTS:
            return True
        return any(host.endswith(s) for s in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []

        from urllib.parse import urlparse
        path = urlparse(event.url).path
        pixel_match = _PIXEL_PATH_RE.match(path)
        if pixel_match:
            params.append(
                ParamInfo(
                    key="(path) property_id",
                    value=pixel_match.group(1),
                    category=CAT_TECHNICAL,
                    meaning="Quantcast property ID embedded in the pixel URL path",
                    privacy_impact=IMPACT_LOW,
                    event_index=event.event_id,
                )
            )

        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Quantcast parameter", IMPACT_LOW)
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
