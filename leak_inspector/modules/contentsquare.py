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

"""Contentsquare (incl. legacy ClickTale + Hotjar via Contentsquare CDN) detector.

Contentsquare is a digital-experience analytics vendor specialising in
session replay, heatmaps, click/scroll tracking, and full-page behaviour
recording. They acquired ClickTale in 2019 and Hotjar in 2021 — the
domains are now all under one vendor's control.
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
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIXES: tuple[str, ...] = (
    ".clicktale.net",
    ".contentsquare.net",
)
_HOST_EXACT: frozenset[str] = frozenset({"clicktale.net", "contentsquare.net"})


_PARAMS: dict[str, tuple[str, str, str]] = {
    "uu":  (CAT_IDENTIFIER, "Contentsquare visitor UUID (stable per visitor)", IMPACT_HIGH),
    "pid": (CAT_TECHNICAL,  "Contentsquare project ID (per-customer)",         IMPACT_LOW),
    "url":   (CAT_CONTENT, "Page URL the event fired on",                      IMPACT_MEDIUM),
    "dr":    (CAT_CONTENT, "Document referrer",                                IMPACT_MEDIUM),
    "fvurl": (CAT_CONTENT, "First-view URL within the session",                IMPACT_MEDIUM),
    "t":     (CAT_CONTENT, "Page title",                                       IMPACT_LOW),
    "v":  (CAT_TECHNICAL, "Contentsquare SDK version (e.g. ``15.225.5``)",     IMPACT_LOW),
    "sn": (CAT_TECHNICAL, "Session number / sequence within the visitor",      IMPACT_LOW),
    "pn": (CAT_TECHNICAL, "Page number / sequence within the session",         IMPACT_LOW),
    "r":  (CAT_TECHNICAL, "Random cache-buster",                               IMPACT_LOW),
    "fvt": (CAT_TECHNICAL, "First-view timestamp (epoch ms)",                  IMPACT_LOW),
    "cvt": (CAT_TECHNICAL, "Current-view timestamp (epoch ms)",                IMPACT_LOW),
    "pvt": (CAT_TECHNICAL, "Page-view timing flag",                            IMPACT_LOW),
    "dw": (CAT_TECHNICAL, "Document width (px)",                               IMPACT_LOW),
    "dh": (CAT_TECHNICAL, "Document height (px)",                              IMPACT_LOW),
    "ww": (CAT_TECHNICAL, "Window viewport width (px)",                        IMPACT_LOW),
    "wh": (CAT_TECHNICAL, "Window viewport height (px)",                       IMPACT_LOW),
    "sw": (CAT_TECHNICAL, "Screen width (px)",                                 IMPACT_LOW),
    "sh": (CAT_TECHNICAL, "Screen height (px)",                                IMPACT_LOW),
    "la": (CAT_TECHNICAL, "Browser language (e.g. ``en-US``)",                 IMPACT_LOW),
    "ri": (CAT_IDENTIFIER, "Recording / replay ID",                            IMPACT_MEDIUM),
}


@register
class ContentsquareModule(TrackerModule):
    """Detect Contentsquare (incl. legacy ClickTale + Hotjar via CSQ CDN) traffic."""

    module_id = "contentsquare"
    module_name = "Contentsquare (incl. ClickTale, Hotjar)"
    vendor = "Contentsquare SAS"
    legal_jurisdiction = "FR"
    data_residency = "EU (Contentsquare is a French company; regional edges include AZ/AF prefixes seen in ``c.az.``, ``k.af.``)"
    sovereignty_notes = "EU controller — GDPR direct, no Schrems II concern; but the data being collected (session replay: clicks, scrolls, form interactions, DOM state) is among the most privacy-sensitive client-side telemetry"
    # privacy 4.5 / security 3.5: session replay (see Clarity) — same
    #   class as the Hotjar/ClickTale brands it now owns. resilience 1.5:
    #   EU vendor (France), but a deep DXP platform with real switching
    #   costs (rubric 1.5) — below the US replay vendors, as jurisdiction
    #   demands.
    impact_rating = ImpactRating(privacy=4.5, security=3.5, resilience=1.5)
    impact_notes = {
        "privacy": "Session replay / experience analytics records clicks, "
            "scrolls, form interaction and DOM state — routinely ingesting "
            "personal data before any submit.",
        "security": "Input/DOM capture by design; a masking slip makes it "
            "a credential and PII harvester.",
        "resilience": "An EU vendor (France), but a deep experience "
            "platform with real switching costs.",
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
                key, (CAT_OTHER, "Unrecognized Contentsquare parameter", IMPACT_LOW)
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
