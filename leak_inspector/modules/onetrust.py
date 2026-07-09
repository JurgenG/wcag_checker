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

"""OneTrust Consent Management Platform detector.

OneTrust is the largest CMP by market share. It delivers a banner SDK,
a per-site consent configuration JSON, and a geolocation lookup to
decide which consent regime applies.

Recognized hosts:

* ``*.onetrust.com`` — OneTrust-owned domains (``geolocation.onetrust.com``,
  ``app-eu.onetrust.com``, etc.).
* ``*.cookielaw.org`` — OneTrust's primary CDN for the banner SDK +
  per-site consent config (``cdn.cookielaw.org/scripttemplates/...``,
  ``cdn.cookielaw.org/consent/<site-uuid>/...``).
* ``*.cookiepro.com`` — OneTrust's small-business / SMB brand.

Per-site identifiers (the OneTrust account UUID) usually ride in the
URL path rather than query params, so the report's representative-hit
URL is where you'll see them. Query strings are typically minimal.

CMP behaviour worth flagging when reading the report: if any tracker
hits (GA4, Meta Pixel, …) fire **before** the OneTrust loader has
completed, that's a misconfiguration — consent should gate trackers,
not the other way round.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
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


_HOST_SUFFIXES: tuple[str, ...] = (
    ".onetrust.com",
    ".cookielaw.org",
    ".cookiepro.com",
)
_HOST_EXACT: frozenset[str] = frozenset({
    "onetrust.com",
    "cookielaw.org",
    "cookiepro.com",
})


_PARAMS: dict[str, tuple[str, str, str]] = {
    "domainData":  (CAT_TECHNICAL,  "OneTrust domain-data identifier",          IMPACT_LOW),
    "tcfVersion":  (CAT_TECHNICAL,  "IAB TCF version requested",                IMPACT_LOW),
    "language":    (CAT_TECHNICAL,  "Banner language",                          IMPACT_LOW),
    "culture":     (CAT_TECHNICAL,  "Banner culture / locale (alt form)",       IMPACT_LOW),
    "v":           (CAT_TECHNICAL,  "Banner SDK version",                       IMPACT_LOW),
    "version":     (CAT_TECHNICAL,  "Banner SDK version (alt form)",            IMPACT_LOW),
    "callback":    (CAT_TECHNICAL,  "Geolocation callback name",                IMPACT_LOW),
    "country":     (CAT_TECHNICAL,  "Country override",                         IMPACT_LOW),
    "state":       (CAT_TECHNICAL,  "Region / state override",                  IMPACT_LOW),
}


@register
class OneTrustModule(TrackerModule):
    """Detect OneTrust CMP loader, configuration, and geolocation requests."""

    module_id = "onetrust"
    module_name = "OneTrust"
    vendor = "OneTrust, LLC"
    legal_jurisdiction = "US"
    data_residency = "US / EU / AU / SG regional data centers"
    sovereignty_notes = "US CLOUD Act applies regardless of regional data-center choice"
    # US third-party CMP: privacy 1.5 (consent record + presence at a
    #   third party). security 3.0 — OneTrust orchestrates and gates other
    #   vendor scripts, so it is effectively a code-loader in the origin
    #   (rubric 3.0, above the lighter EU CMPs' 2.5). resilience 2.5 (US —
    #   rubric 2.5).
    impact_rating = ImpactRating(privacy=1.5, security=3.0, resilience=2.5)
    impact_notes = {
        "privacy": "A consent record plus presence telemetry at a "
            "third-party CMP.",
        "security": "Orchestrates and gates other vendors' scripts — "
            "effectively a code-loader in your origin.",
        "resilience": "A US-controlled consent layer.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _HOST_EXACT:
            return True
        return any(host.endswith(suffix) for suffix in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized OneTrust parameter", IMPACT_LOW)
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
