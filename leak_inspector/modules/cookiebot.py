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

"""Cookiebot Consent Management Platform detector.

Cookiebot (now owned by Usercentrics) is a widely-deployed CMP in
Europe. The browser SDK loads from ``consent.cookiebot.com`` and ships
a per-site UUID (``cbid``) plus locale info on its loader URL.

Recognized hosts:

* ``*.cookiebot.com`` — primary CMP host.
* ``*.cookiebot.eu`` — EU region.

The per-site Cookiebot identifier (``cbid``) is the most-useful
classifiable field; the rest is locale + script-version plumbing.
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


_HOST_SUFFIXES: tuple[str, ...] = (".cookiebot.com", ".cookiebot.eu")
_HOST_EXACT: frozenset[str] = frozenset({"cookiebot.com", "cookiebot.eu"})


_PARAMS: dict[str, tuple[str, str, str]] = {
    "cbid":     (CAT_TECHNICAL,  "Cookiebot per-site UUID",                     IMPACT_LOW),
    "culture":  (CAT_TECHNICAL,  "Banner culture / locale",                     IMPACT_LOW),
    "language": (CAT_TECHNICAL,  "Banner language",                             IMPACT_LOW),
    "version":  (CAT_TECHNICAL,  "Banner SDK version",                          IMPACT_LOW),
    "v":        (CAT_TECHNICAL,  "Banner SDK version (alt form)",               IMPACT_LOW),
    "type":     (CAT_TECHNICAL,  "Request type (script / config)",              IMPACT_LOW),
    "framework": (CAT_TECHNICAL, "TCF / IAB framework identifier",              IMPACT_LOW),
}


@register
class CookiebotModule(TrackerModule):
    """Detect Cookiebot CMP loader and configuration requests."""

    module_id = "cookiebot"
    module_name = "Cookiebot"
    vendor = "Usercentrics GmbH (formerly Cybot A/S)"
    legal_jurisdiction = "DE"
    data_residency = "EU (Germany / Denmark)"
    sovereignty_notes = ""
    # Third-party hosted CMP (the consent mechanism, but externally
    # hosted — costs more than a self-hosted banner): privacy 1.5
    #   (consent record + presence telemetry at a third party). security
    #   2.5 (unpinned CMP JS in the origin). resilience 1.0 (EU vendor,
    #   Germany/Denmark, GDPR-native — rubric 1.0).
    impact_rating = ImpactRating(privacy=1.5, security=2.5, resilience=1.0)
    impact_notes = {
        "privacy": "A consent record plus presence telemetry at a "
            "third-party CMP (the EU hosted variant).",
        "security": "Loads an unpinned CMP script into your origin.",
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
                key, (CAT_OTHER, "Unrecognized Cookiebot parameter", IMPACT_LOW)
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
