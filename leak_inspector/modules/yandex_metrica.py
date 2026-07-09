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

"""Yandex.Metrica (Яндекс.Метрика) detector.

Yandex's flagship web-analytics product. WebVisor session replay is
shipped in the box and enabled by default on newer accounts — same
privacy class as Microsoft Clarity / Hotjar / FullStory when WebVisor
is on.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_PII,
    CAT_TECHNICAL,
    Hit,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_MC_YANDEX_RE = re.compile(r"^mc\.yandex\.[a-z]{2,4}(\.[a-z]{2,4})?$")

_WEBVISOR_HOSTS: frozenset[str] = frozenset({
    "mc.webvisor.org",
    "mc.webvisor.com",
})

_PATH_PATTERNS: tuple[tuple[re.Pattern, str, str, str, str], ...] = (
    (
        re.compile(r"^/watch/(\d+)/1(?:/|$|\?)"),
        "(path) webvisor_counter_id",
        CAT_TECHNICAL,
        "Metrica counter ID (WebVisor session-replay upload endpoint — the per-customer ID itself is technical/low; the WebVisor-active indication is surfaced separately in the executive summary)",
        IMPACT_LOW,
    ),
    (
        re.compile(r"^/watch/(\d+)(?:/|$|\?)"),
        "(path) counter_id",
        CAT_TECHNICAL,
        "Metrica counter ID (per-customer site key) — extracted from URL path",
        IMPACT_LOW,
    ),
    (
        re.compile(r"^/clmap/(\d+)(?:/|$|\?)"),
        "(path) clmap_counter_id",
        CAT_TECHNICAL,
        "Metrica counter ID (click-map ingest)",
        IMPACT_LOW,
    ),
    (
        re.compile(r"^/informer/(\d+)(?:/|$|\?)"),
        "(path) informer_counter_id",
        CAT_TECHNICAL,
        "Metrica counter ID (public counter widget)",
        IMPACT_LOW,
    ),
)


_PARAMS: dict[str, tuple[str, str, str]] = {
    "i":       (CAT_IDENTIFIER, "Persistent visitor pseudonym (the ``_ym_uid`` cookie)", IMPACT_HIGH),
    "ym_uid":  (CAT_IDENTIFIER, "Persistent visitor pseudonym (alt form)",      IMPACT_HIGH),
    "u":       (CAT_IDENTIFIER, "Session identifier (per-session, not visitor-persistent — see ``i`` / ``ym_uid`` for the persistent pseudonym)", IMPACT_MEDIUM),
    "uid":     (CAT_PII,        "Site-supplied user ID",                        IMPACT_HIGH),
    "ut":      (CAT_TECHNICAL,  "User type flag",                               IMPACT_LOW),
    "wmode":     (CAT_BEHAVIORAL, "Hit mode (0=js-with-images, 1=js-no-images, 2=image-only, …)", IMPACT_LOW),
    "ev-id":     (CAT_BEHAVIORAL, "Event ID",                                   IMPACT_MEDIUM),
    "ev-type":   (CAT_BEHAVIORAL, "Event type",                                 IMPACT_MEDIUM),
    "ar":        (CAT_TECHNICAL,  "Aspect ratio",                               IMPACT_LOW),
    "et":        (CAT_BEHAVIORAL, "Engagement time",                            IMPACT_LOW),
    "nt":        (CAT_BEHAVIORAL, "New-visitor flag",                           IMPACT_LOW),
    "goal-id":   (CAT_BEHAVIORAL, "Conversion-goal ID",                         IMPACT_MEDIUM),
    "params":    (CAT_BEHAVIORAL, "Custom event-params JSON blob",              IMPACT_MEDIUM),
    "experiments": (CAT_BEHAVIORAL, "A/B experiments the visitor is bucketed into", IMPACT_MEDIUM),
    "is-iframe": (CAT_TECHNICAL,  "Hit fired from an iframe",                   IMPACT_LOW),
    "wv":             (CAT_TECHNICAL,  "WebVisor protocol version",             IMPACT_LOW),
    "wv-page-id":     (CAT_IDENTIFIER, "WebVisor per-page-load ID",             IMPACT_MEDIUM),
    "wv-load-id":     (CAT_IDENTIFIER, "WebVisor load ID",                      IMPACT_MEDIUM),
    "wv-type":        (CAT_BEHAVIORAL, "WebVisor record type (events / mouse / form)", IMPACT_HIGH),
    "wv-part":        (CAT_TECHNICAL,  "WebVisor chunk sequence",               IMPACT_LOW),
    "page-url": (CAT_CONTENT, "Page URL",                                       IMPACT_MEDIUM),
    "dl":       (CAT_CONTENT, "Document location",                              IMPACT_MEDIUM),
    "page-ref": (CAT_CONTENT, "Document referrer",                              IMPACT_MEDIUM),
    "r":        (CAT_CONTENT, "Referrer URL",                                   IMPACT_MEDIUM),
    "t":        (CAT_CONTENT, "Page title",                                     IMPACT_LOW),
    "ds":       (CAT_TECHNICAL, "Document size",                                IMPACT_LOW),
    "tot-load-time":      (CAT_TECHNICAL, "Total load time (ms)",               IMPACT_LOW),
    "dom-content-loaded": (CAT_TECHNICAL, "DOMContentLoaded time (ms)",         IMPACT_LOW),
    "load-event":         (CAT_TECHNICAL, "load-event time (ms)",               IMPACT_LOW),
    "ms-since-page-load": (CAT_TECHNICAL, "ms since page-load",                 IMPACT_LOW),
    "vp":   (CAT_TECHNICAL, "Viewport size",                                    IMPACT_LOW),
    "ws":   (CAT_TECHNICAL, "Window size",                                      IMPACT_LOW),
    "s":    (CAT_TECHNICAL, "Screen color depth",                               IMPACT_LOW),
    "z":    (CAT_TECHNICAL, "Time zone offset",                                 IMPACT_LOW),
    "cnt-class":    (CAT_BEHAVIORAL, "Counter class (visitor-category bucket)", IMPACT_LOW),
    "cnt-cw":       (CAT_TECHNICAL, "Content client width",                     IMPACT_LOW),
    "cnt-ch":       (CAT_TECHNICAL, "Content client height",                    IMPACT_LOW),
    "cnt-resize-w": (CAT_TECHNICAL, "Content width after resize",               IMPACT_LOW),
    "cnt-resize-h": (CAT_TECHNICAL, "Content height after resize",              IMPACT_LOW),
    "browser-info": (CAT_TECHNICAL, "Encoded browser-features blob",            IMPACT_LOW),
    "consent":  (CAT_CONSENT, "Consent state",                                  IMPACT_LOW),
    "gdpr":     (CAT_CONSENT, "GDPR-applies flag",                              IMPACT_LOW),
    "rn":  (CAT_TECHNICAL, "Random cache-buster",                               IMPACT_LOW),
    "c":   (CAT_TECHNICAL, "Counter-mode flag",                                 IMPACT_LOW),
    "cv":  (CAT_TECHNICAL, "Counter (script) version",                          IMPACT_LOW),
}


@register
class YandexMetricaModule(TrackerModule):
    """Detect Yandex.Metrica page-view, event, and WebVisor session-replay traffic."""

    module_id = "yandex_metrica"
    module_name = "Yandex.Metrica"
    vendor = "Yandex LLC"
    legal_jurisdiction = "RU"
    data_residency = "Russia (Yandex data centers)"
    sovereignty_notes = "Russian Federal Law 152-FZ applies; Russian authorities can compel data disclosure. WebVisor mode adds session replay."
    # Yandex's web analytics (Russia's GA equivalent): privacy 3.0
    #   (behavioural profile, base; WebVisor session replay — when its
    #   beacon is observed — is the rubric-4.5 case, a Phase-5 variant).
    # security 2.5 (unpinned tag). resilience 3.0 (RU measurement layer —
    #   foreign-controlled, high-risk; rubric 3.0).
    impact_rating = ImpactRating(privacy=3.0, security=2.5, resilience=3.0)
    impact_notes = {
        "privacy": "Yandex's web analytics builds a behavioural profile "
            "at a self-interested controller (Russia's GA equivalent); "
            "WebVisor session replay, when on, is worse still.",
        "security": "Loads an unpinned analytics tag into your origin.",
        "resilience": "A Russia-controlled measurement layer — high-risk "
            "jurisdiction.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _WEBVISOR_HOSTS:
            return True
        return bool(_MC_YANDEX_RE.match(host))

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Yandex.Metrica parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key, value=value, category=category, meaning=meaning,
                    privacy_impact=impact, event_index=event.event_id,
                )
            )
        path = urlparse(event.url).path
        for pattern, key, category, meaning, impact in _PATH_PATTERNS:
            match = pattern.match(path)
            if match:
                params.append(
                    ParamInfo(
                        key=key, value=match.group(1), category=category,
                        meaning=meaning, privacy_impact=impact,
                        event_index=event.event_id,
                    )
                )
                break
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
