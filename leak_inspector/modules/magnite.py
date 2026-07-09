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

"""Magnite SSP detector (formerly Rubicon Project + Telaria).

Magnite is the SSP formed from the 2020 merger of Rubicon Project and
Telaria; the original Rubicon ad-serving infrastructure remains live
under ``*.rubiconproject.com``, with CTV-specific paths inherited
from Telaria.

Recognized hosts: ``*.rubiconproject.com`` (legacy Rubicon ad serving
— ``pixel.rubiconproject.com``, ``optimized-by.rubiconproject.com``,
``token.rubiconproject.com``, etc.) and ``*.magnite.com`` (newer
Magnite-branded serving). Notable paths:

* ``/tap.php`` — cookie-sync ``put`` pixel (sets a Rubicon cookie
  with the value passed in the ``put`` parameter).
* ``/cs/sync.html`` and ``/cs/v1/`` — cookie-sync HTML / JSON handlers.
* ``/exapi.js`` and ``/loader.js`` — bidder-loader bundles.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_CONSENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_HIGH,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIXES = (".rubiconproject.com", ".magnite.com")
_HOST_EXACTS = {"rubiconproject.com", "magnite.com"}


_PARAMS: dict[str, tuple[str, str, str]] = {
    "v":         (CAT_TECHNICAL,  "Vendor / partner ID (in /tap.php)",          IMPACT_LOW),
    "nid":       (CAT_TECHNICAL,  "Network / publisher ID",                     IMPACT_LOW),
    "put":       (CAT_IDENTIFIER, "Cookie value to set (the partner's user ID synced into Magnite)", IMPACT_HIGH),
    "expires":   (CAT_TECHNICAL, "Cookie expiry in days",                       IMPACT_LOW),
    "gdpr":         (CAT_CONSENT, "GDPR-applies flag (0/1)",                     IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "IAB TCF consent string",                      IMPACT_LOW),
    "us_privacy":   (CAT_CONSENT, "IAB CCPA US-privacy string",                  IMPACT_LOW),
    "redirect":  (CAT_TECHNICAL, "Redirect target after sync completes",         IMPACT_LOW),
}


@register
class MagniteModule(TrackerModule):
    """Detect Magnite / Rubicon Project SSP cookie-sync and bidder traffic."""

    module_id = "magnite"
    module_name = "Magnite (Rubicon Project)"
    vendor = "Magnite, Inc."
    legal_jurisdiction = "US"
    data_residency = "US (New York, NY HQ); global serving infrastructure"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # SSP (Rubicon): privacy 4.0, security 4.0 (OpenRTB sync chain),
    # resilience 2.5 (US supporting). See appnexus for the shared shape.
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=2.5)
    impact_notes = {
        "privacy": "An SSP (Rubicon) that joins this visit to a web-wide "
            "advertising profile — cross-site by design.",
        "security": "OpenRTB auctions and a sync chain redirect the "
            "visitor into demand partners you cannot enumerate.",
        "resilience": "A US ad-revenue dependency, replaceable but "
            "foreign-controlled.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _HOST_EXACTS:
            return True
        return any(host.endswith(s) for s in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Magnite parameter", IMPACT_LOW)
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
