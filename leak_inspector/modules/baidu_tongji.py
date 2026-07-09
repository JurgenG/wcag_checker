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

"""Baidu Tongji (百度统计) detector.

Baidu's web-analytics service — by far the most-deployed analytics
platform on Chinese-language sites. Functionally comparable to GA4.

The browser SDK loads ``hm.baidu.com/hm.js?<site_id>`` and ships
events as a GET request to ``hm.baidu.com/hm.gif`` with a richly
structured query string. The per-site identifier (the *site ID*,
analogous to GA4's measurement ID) is the path argument of the loader
and a query field (``si``) on every collect.

Recognized hosts:

* ``hm.baidu.com`` — primary loader + collect host.
* ``hmcdn.baidu.com`` — script CDN seen on some properties.

Parameter dictionary below covers the well-known fields from Baidu's
publicly-documented and observed tracking-pixel schema; unknown keys
fall through to ``CAT_OTHER`` so we still record them.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
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


_HOST_EXACT: frozenset[str] = frozenset({
    "hm.baidu.com",
    "hmcdn.baidu.com",
})


_PARAMS: dict[str, tuple[str, str, str]] = {
    "si":  (CAT_TECHNICAL,  "Baidu Tongji site ID (per-customer counter key)", IMPACT_LOW),
    "v":   (CAT_TECHNICAL,  "Tracking protocol version",                       IMPACT_LOW),
    "cv":  (CAT_TECHNICAL,  "Client (script) version",                         IMPACT_LOW),
    "u":   (CAT_CONTENT,    "Page URL",                                        IMPACT_MEDIUM),
    "su":  (CAT_CONTENT,    "Source URL (document referrer)",                  IMPACT_MEDIUM),
    "tt":  (CAT_CONTENT,    "Page title",                                      IMPACT_LOW),
    "hn":  (CAT_CONTENT,    "Hostname of the calling page",                    IMPACT_LOW),
    "lo":  (CAT_CONTENT,    "Location pathname",                               IMPACT_LOW),
    "nv":  (CAT_BEHAVIORAL, "New-visitor flag",                                IMPACT_LOW),
    "lt":  (CAT_BEHAVIORAL, "Visitor's last-visit timestamp (visit recency)",  IMPACT_LOW),
    "st":  (CAT_BEHAVIORAL, "Traffic source type",                             IMPACT_LOW),
    "hca": (CAT_TECHNICAL,  "Has-called-analytics flag (always 1)",            IMPACT_LOW),
    "cc":  (CAT_TECHNICAL,  "Cookie-support flag",                             IMPACT_LOW),
    "ck":  (CAT_TECHNICAL,  "Cookie-test flag",                                IMPACT_LOW),
    "ep":     (CAT_BEHAVIORAL, "Engagement-time / event-params bundle",        IMPACT_MEDIUM),
    "et":     (CAT_BEHAVIORAL, "Event type",                                   IMPACT_MEDIUM),
    "se_cat": (CAT_BEHAVIORAL, "Event category",                               IMPACT_MEDIUM),
    "se_id":  (CAT_IDENTIFIER, "Event ID",                                     IMPACT_LOW),
    "se_la":  (CAT_BEHAVIORAL, "Event label",                                  IMPACT_MEDIUM),
    "se_va":  (CAT_BEHAVIORAL, "Event value",                                  IMPACT_MEDIUM),
    "ds":  (CAT_TECHNICAL, "Document size (page width × height)",              IMPACT_LOW),
    "sw":  (CAT_TECHNICAL, "Screen width",                                     IMPACT_LOW),
    "sh":  (CAT_TECHNICAL, "Screen height",                                    IMPACT_LOW),
    "ww":  (CAT_TECHNICAL, "Window width",                                     IMPACT_LOW),
    "wh":  (CAT_TECHNICAL, "Window height",                                    IMPACT_LOW),
    "cl":  (CAT_TECHNICAL, "Client (screen) color depth",                      IMPACT_LOW),
    "ln":  (CAT_TECHNICAL, "Browser language",                                 IMPACT_LOW),
    "ja":  (CAT_TECHNICAL, "Java-enabled flag (legacy fingerprint surface)",   IMPACT_LOW),
    "fl":  (CAT_TECHNICAL, "Flash-plugin version (legacy)",                    IMPACT_LOW),
    "sb":  (CAT_TECHNICAL, "Safari-indicator flag",                            IMPACT_LOW),
    "_t":  (CAT_TECHNICAL, "Client-side timestamp",                            IMPACT_LOW),
    "_p":  (CAT_TECHNICAL, "Page-load nonce",                                  IMPACT_LOW),
    "_h":  (CAT_TECHNICAL, "Page-hash plumbing",                               IMPACT_LOW),
    "rnd": (CAT_TECHNICAL, "Random cache-buster",                              IMPACT_LOW),
    "uid": (CAT_PII, "Site-supplied user ID",                                  IMPACT_HIGH),
}


@register
class BaiduTongjiModule(TrackerModule):
    """Detect Baidu Tongji (百度统计) loader and ``hm.gif`` collect traffic."""

    module_id = "baidu_tongji"
    module_name = "Baidu Tongji (百度统计)"
    vendor = "Baidu, Inc."
    legal_jurisdiction = "CN"
    data_residency = "China (Baidu data centers)"
    sovereignty_notes = "PRC Cybersecurity Law and Data Security Law apply; authorities can compel data disclosure"
    # Baidu's web analytics (China's GA equivalent): privacy 3.0
    #   (behavioural profile at a self-interested controller — same shape
    #   as GA4; jurisdiction lives on the resilience axis, not privacy).
    # security 2.5 (unpinned analytics tag). resilience 3.0 (CN measurement
    #   layer — foreign-controlled, high-risk; rubric 3.0).
    impact_rating = ImpactRating(privacy=3.0, security=2.5, resilience=3.0)
    impact_notes = {
        "privacy": "Baidu's web analytics builds a behavioural profile at "
            "a self-interested controller (China's GA equivalent).",
        "security": "Loads an unpinned analytics tag into your origin.",
        "resilience": "A China-controlled measurement layer — high-risk "
            "jurisdiction.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return event.host.lower() in _HOST_EXACT

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Baidu Tongji parameter", IMPACT_LOW)
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
