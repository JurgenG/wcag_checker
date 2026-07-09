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

"""Microsoft Bing UET (Universal Event Tracking) detector.

Bing UET is Microsoft Advertising's web-event pixel — equivalent to Meta
Pixel / GA4 in scope, used for Bing Ads conversion tracking and
audience targeting.

Recognized hosts: ``bat.bing.com``, ``bat.bing.net``, ``bat.r.msn.com``,
``c.bing.com`` (Microsoft Advertising cookie-sync pixel).
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_EXACT: frozenset[str] = frozenset({
    "bat.bing.com",
    "bat.bing.net",
    "bat.r.msn.com",
    "c.bing.com",
})


_PARAMS: dict[str, tuple[str, str, str]] = {
    "ti":      (CAT_TECHNICAL,  "UET tag ID (per-customer tracking key)",       IMPACT_LOW),
    "mid":     (CAT_IDENTIFIER, "Machine / persistent visitor pseudonym (UUID)", IMPACT_HIGH),
    "vid":     (CAT_IDENTIFIER, "Visitor ID (UUID, persistent across sessions)", IMPACT_HIGH),
    "sid":     (CAT_IDENTIFIER, "Session ID (per-session, not visitor-persistent)", IMPACT_MEDIUM),
    "pi":      (CAT_IDENTIFIER, "Page-load ID",                                  IMPACT_MEDIUM),
    "msclkid": (CAT_IDENTIFIER, "Microsoft Advertising click identifier",        IMPACT_MEDIUM),
    "vids":    (CAT_BEHAVIORAL, "Visit count for this visitor",                  IMPACT_LOW),
    "MXFR":      (CAT_IDENTIFIER, "Microsoft cross-domain user identifier (32-char hex)",   IMPACT_HIGH),
    "uid":       (CAT_IDENTIFIER, "Sync-partner user identifier",                            IMPACT_HIGH),
    "CtsSyncId": (CAT_IDENTIFIER, "Cookie-sync correlation ID",                              IMPACT_MEDIUM),
    "RedC":      (CAT_CONTENT,    "Cookie-sync redirect target host",                        IMPACT_MEDIUM),
    "Red3":      (CAT_CONTENT,    "Cookie-sync chain partner identifier",                    IMPACT_MEDIUM),
    "evt": (CAT_BEHAVIORAL, "Event type (PageLoad, custom name, ``consent``, …)", IMPACT_MEDIUM),
    "ec":  (CAT_BEHAVIORAL, "Event category",                                   IMPACT_MEDIUM),
    "ea":  (CAT_BEHAVIORAL, "Event action",                                     IMPACT_MEDIUM),
    "el":  (CAT_BEHAVIORAL, "Event label",                                      IMPACT_MEDIUM),
    "ev":  (CAT_BEHAVIORAL, "Event value",                                      IMPACT_MEDIUM),
    "gv":  (CAT_BEHAVIORAL, "Goal / conversion value",                          IMPACT_MEDIUM),
    "gid": (CAT_TECHNICAL,  "Goal / conversion ID",                             IMPACT_LOW),
    "src": (CAT_BEHAVIORAL, "Event source code",                                IMPACT_LOW),
    "p":  (CAT_CONTENT, "Page URL",                                             IMPACT_MEDIUM),
    "r":  (CAT_CONTENT, "Document referrer",                                    IMPACT_MEDIUM),
    "tl": (CAT_CONTENT, "Page title",                                           IMPACT_LOW),
    "kw": (CAT_CONTENT, "Page keywords",                                        IMPACT_LOW),
    "lg": (CAT_TECHNICAL, "Browser language",                                   IMPACT_LOW),
    "sw": (CAT_TECHNICAL, "Screen width",                                       IMPACT_LOW),
    "sh": (CAT_TECHNICAL, "Screen height",                                      IMPACT_LOW),
    "sc": (CAT_TECHNICAL, "Screen color depth",                                 IMPACT_LOW),
    "tz": (CAT_TECHNICAL, "Timezone offset",                                    IMPACT_LOW),
    "cdb": (CAT_CONSENT, "Encoded consent-data blob",                           IMPACT_MEDIUM),
    "asc": (CAT_CONSENT, "Ad-serving consent flag",                             IMPACT_LOW),
    "gdpr":         (CAT_CONSENT, "GDPR-applies flag",                          IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "TCF consent string",                         IMPACT_LOW),
    "Ver":  (CAT_TECHNICAL, "UET protocol version",                             IMPACT_LOW),
    "tm":   (CAT_TECHNICAL, "Tag method (``gtm002`` = loaded via GTM v2 etc.)", IMPACT_LOW),
    "bo":   (CAT_TECHNICAL, "Beacon / batch order",                             IMPACT_LOW),
    "rn":   (CAT_TECHNICAL, "Random cache-buster",                              IMPACT_LOW),
}


@register
class BingUETModule(TrackerModule):
    """Detect Microsoft Bing UET loader, action, and consent traffic."""

    module_id = "bing_uet"
    module_name = "Microsoft Bing UET"
    vendor = "Microsoft Corporation (Bing Ads)"
    legal_jurisdiction = "US"
    data_residency = "Microsoft global infrastructure"
    sovereignty_notes = "US CLOUD Act applies"
    # privacy 4.0: Microsoft Advertising's web-event pixel — conversion
    #   tracking + audience targeting across Bing's ad network, cross-site
    #   by design (rubric privacy 4.0). security 2.5: ordinary unpinned
    #   pixel. resilience 3.0: foreign (US) ads/audience layer, replaceable
    #   supporting channel (rubric 3.0).
    impact_rating = ImpactRating(privacy=4.0, security=2.5, resilience=3.0)
    impact_notes = {
        "privacy": "Microsoft Advertising's event pixel tracks conversions "
            "and builds audiences across Bing's ad network — cross-site by "
            "design.",
        "security": "Loads an unpinned Microsoft pixel into your origin.",
        "resilience": "A US ads/audience layer the outreach depends on.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return event.host.lower() in _HOST_EXACT

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Bing UET parameter", IMPACT_LOW)
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
