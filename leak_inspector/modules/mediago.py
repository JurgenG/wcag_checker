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

"""Mediago (Bytedance) native-advertising network detector.

Mediago is a programmatic native-ad SSP/DSP operated by Bytedance
(TikTok / ByteDance). It serves native ad units, runs auctions, syncs
cookies with downstream demand partners (AppNexus, Google, etc.), and
logs viewability / impression events.

Recognized hosts: every subdomain of ``mediago.io``.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
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


_HOST_SUFFIX = ".mediago.io"
_HOST_EXACT = "mediago.io"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "uid":         (CAT_IDENTIFIER, "User identifier (value origin varies: Mediago UUID, numeric, or partner gid)", IMPACT_HIGH),
    "mguid":       (CAT_IDENTIFIER, "Mediago user ID (mirror of the ``__mguid_`` cookie)", IMPACT_HIGH),
    "rdid":        (CAT_IDENTIFIER, "Identifier exchanged at cookie-sync endpoints (32-char hex)", IMPACT_HIGH),
    "google_gid":  (CAT_IDENTIFIER, "Google cookie-sync identifier",                   IMPACT_HIGH),
    "google_push": (CAT_IDENTIFIER, "Google cookie-sync push token",                   IMPACT_HIGH),
    "tn":         (CAT_TECHNICAL, "Stable per-publisher token (observed: 2 distinct values across 101 requests)", IMPACT_LOW),
    "trackingid": (CAT_IDENTIFIER, "Per-event tracking handle (32-char hex, varies per request)", IMPACT_MEDIUM),
    "acid":       (CAT_IDENTIFIER, "Numeric ID (observed: ``28511``, ``30739``)",     IMPACT_LOW),
    "data": (CAT_BEHAVIORAL, "Opaque encoded payload",                                 IMPACT_MEDIUM),
    "app":  (CAT_BEHAVIORAL, "Mediago event channel (observed: ``vimpLog``, ``MEDIA_INFO``)", IMPACT_MEDIUM),
    "ext":  (CAT_BEHAVIORAL, "Event payload JSON (e.g. ``name``, ``vimp_elapsed_time``, ``intersectCount``)", IMPACT_MEDIUM),
    "c_sync":      (CAT_TECHNICAL, "Cookie-sync flag",                                 IMPACT_LOW),
    "dm":          (CAT_TECHNICAL, "Cookie-sync destination URL",                      IMPACT_LOW),
    "google_cver": (CAT_TECHNICAL, "Google consent / cookie-sync version",             IMPACT_LOW),
    "gdpr":         (CAT_CONSENT, "IAB TCF: GDPR-applies flag",                        IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "IAB TCF consent string",                            IMPACT_LOW),
    "mcb": (CAT_TECHNICAL, "Cache-buster (format: ``mmgg_<ts>_<rand>``)",              IMPACT_LOW),
}


@register
class MediagoModule(TrackerModule):
    """Detect Mediago (Bytedance) native-ad serving, tracking, and cookie-sync traffic."""

    module_id = "mediago"
    module_name = "Mediago (Bytedance)"
    vendor = "Beijing Bytedance Technology Co. Ltd."
    legal_jurisdiction = "China"
    data_residency = "China headquarters with regional edge (``trace-eu.`` for EU traffic)"
    sovereignty_notes = "PRC jurisdiction — Cybersecurity Law / Data Security Law / PIPL apply"
    # Native-ad SSP/DSP (Bytedance): privacy 4.0 (cross-site, cookie-sync
    #   to downstream demand), security 4.0 (auction + sync chain).
    # resilience 2.5: China is high-risk jurisdiction, native ads a
    #   replaceable supporting feature (rubric 2.5). NB the current
    #   rubric does not rank CN above US within the high-risk class — a
    #   rubric question, not a per-module call.
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=2.5)
    impact_notes = {
        "privacy": "A native-ad SSP/DSP (ByteDance) that joins this visit "
            "to a web-wide advertising profile — cross-site by design.",
        "security": "Auctions and cookie-sync redirect the visitor into "
            "demand partners you cannot enumerate.",
        "resilience": "A China-controlled ad dependency — high-risk "
            "jurisdiction, replaceable channel.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Mediago parameter", IMPACT_LOW)
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
