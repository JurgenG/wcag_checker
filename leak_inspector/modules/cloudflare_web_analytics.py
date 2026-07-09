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

"""Cloudflare Web Analytics detector.

Cloudflare's "privacy-first" RUM product. The browser SDK loads a small
``beacon.min.js`` from ``static.cloudflareinsights.com`` and ships a
page-view + performance payload to either:

* ``static.cloudflareinsights.com/cdn-cgi/rum`` — third-party host form, or
* ``<the-visited-site>/cdn-cgi/rum`` — the first-party-relayed form,
  proxied through the site's own Cloudflare edge so the request looks
  same-origin to the browser.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
    CAT_CONTENT,
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


_LOADER_HOST = "static.cloudflareinsights.com"
_RUM_PATH = "/cdn-cgi/rum"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "token": (CAT_TECHNICAL,  "Per-site Cloudflare Web Analytics token (account identifier)", IMPACT_LOW),
    "b":  (CAT_BEHAVIORAL, "Beacon type indicator",                              IMPACT_LOW),
    "bv": (CAT_TECHNICAL,  "Beacon-format version",                              IMPACT_LOW),
    "t":  (CAT_TECHNICAL,  "Token (alternate form of ``token``)",                IMPACT_LOW),
    "si": (CAT_TECHNICAL,  "Sample-interval indicator",                          IMPACT_LOW),
    "rv": (CAT_TECHNICAL,  "RUM script revision",                                IMPACT_LOW),
    "url":      (CAT_CONTENT, "Page URL the beacon fired on",                    IMPACT_MEDIUM),
    "referrer": (CAT_CONTENT, "Document referrer",                               IMPACT_MEDIUM),
}


def _parse_data_blob(raw: str | None) -> list[ParamInfo]:
    if not raw:
        return []
    try:
        decoded = json.loads(raw)
    except (ValueError, TypeError):
        return []
    if not isinstance(decoded, dict):
        return []

    extracted: list[ParamInfo] = []

    site_id = decoded.get("si")
    if site_id:
        extracted.append(ParamInfo(
            key="(body) data.site_id",
            value=str(site_id),
            category=CAT_TECHNICAL,
            meaning="Cloudflare Analytics site ID (inside the encoded data blob)",
            privacy_impact=IMPACT_LOW,
            event_index=0,
        ))

    page_list = decoded.get("li")
    if isinstance(page_list, list) and page_list:
        extracted.append(ParamInfo(
            key="(body) data.page_count",
            value=str(len(page_list)),
            category=CAT_BEHAVIORAL,
            meaning="Number of pages / resources reported in this beacon",
            privacy_impact=IMPACT_MEDIUM,
            event_index=0,
        ))
        first = page_list[0] if isinstance(page_list[0], dict) else {}
        first_url = first.get("u")
        if first_url:
            extracted.append(ParamInfo(
                key="(body) data.first_page_url",
                value=str(first_url),
                category=CAT_CONTENT,
                meaning="First page URL reported in the beacon's page list",
                privacy_impact=IMPACT_MEDIUM,
                event_index=0,
            ))

    return extracted


@register
class CloudflareWebAnalyticsModule(TrackerModule):
    """Detect Cloudflare Web Analytics loader and RUM beacons."""

    module_id = "cloudflare_web_analytics"
    module_name = "Cloudflare Web Analytics"
    vendor = "Cloudflare, Inc."
    legal_jurisdiction = "US"
    data_residency = "Cloudflare global edge (closest PoP)"
    sovereignty_notes = "US CLOUD Act applies; marketed as privacy-first but still under US jurisdiction"
    # Cookieless aggregate analytics: privacy 1.0 (no cookies, no
    #   persistent visitor ID — presence/aggregate counts; rubric 1.0,
    #   below profiling). security 2.0 (unpinned beacon snippet).
    #   resilience 2.0 (US Cloudflare, replaceable — rubric 2.0).
    impact_rating = ImpactRating(privacy=1.0, security=2.0, resilience=2.0)
    impact_notes = {
        "security": "Loads an unpinned beacon script into your origin.",
        "resilience": "A US-controlled analytics vendor — replaceable.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host == _LOADER_HOST:
            return True
        path = urlparse(event.url).path
        return path == _RUM_PATH

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        data_field: str | None = None
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Cloudflare Web Analytics parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key, value=value, category=category, meaning=meaning,
                    privacy_impact=impact, event_index=event.event_id,
                )
            )
            if key == "data":
                data_field = value

        for body_param in _parse_data_blob(data_field):
            body_param.event_index = event.event_id
            params.append(body_param)
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
