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

"""Google Tag Manager detector.

GTM itself does not exfiltrate measurement data — it is a loader. But
seeing GTM hits in a capture tells you:

* the container ID the site is running (``GTM-XXXXXX`` or, for direct
  gtag-managed properties, the GA4 measurement ID ``G-XXXXXX``);
* which environment / workspace is published (``gtm_auth`` /
  ``gtm_preview``);
* whether server-side GTM is in use (``/gtm/collect`` endpoints).

The actual data leaks happen in the trackers GTM subsequently loads
(GA4, Facebook Pixel, Floodlight, Hotjar, …). Those are caught by their
respective modules; this one provides the audit-trail context.

Recognized hosts: ``www.googletagmanager.com`` and any ``*.googletagmanager.com``.
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


_HOST_SUFFIX = ".googletagmanager.com"
_HOST_EXACT = "googletagmanager.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "id": (
        CAT_TECHNICAL,
        "Container ID (GTM-XXXX) or GA4 measurement ID (G-XXXX)",
        IMPACT_LOW,
    ),
    "gtm_auth": (
        CAT_TECHNICAL,
        "GTM environment auth token (selects published workspace)",
        IMPACT_LOW,
    ),
    "gtm_preview": (
        CAT_TECHNICAL,
        "GTM preview environment hash",
        IMPACT_LOW,
    ),
    "gtm_cookies_win": (
        CAT_TECHNICAL,
        "Cookie-window flag passed by the GTM loader",
        IMPACT_LOW,
    ),
    "l": (
        CAT_TECHNICAL,
        "Custom dataLayer variable name (default: ``dataLayer``)",
        IMPACT_LOW,
    ),
    "cx": (
        CAT_TECHNICAL,
        "Loader context indicator (newer GTM)",
        IMPACT_LOW,
    ),
    "cb": (
        CAT_TECHNICAL,
        "Cache-buster",
        IMPACT_LOW,
    ),
    "gtm": (
        CAT_TECHNICAL,
        "GTM container / workspace / version string",
        IMPACT_LOW,
    ),
}


@register
class GoogleTagManagerModule(TrackerModule):
    """Detect Google Tag Manager loader and server-side endpoints."""

    module_id = "googletagmanager"
    module_name = "Google Tag Manager"
    vendor = "Google LLC"
    legal_jurisdiction = "US"
    data_residency = "Google global CDN"
    sovereignty_notes = "GTM itself is a loader, but every tracker it loads becomes a transfer to that tracker's vendor (often Google itself: GA4 / Ads / Floodlight)"
    # privacy 1.5: the container ships almost no visitor data itself —
    #   anonymous config/audit telemetry (rubric 1.5); the trackers it
    #   loads are scored by their own modules. security 3.0: its very
    #   function is to load further arbitrary code into the first-party
    #   origin — the rubric's "code loader / broad-access" line.
    #   resilience 2.5: replaceable supporting layer on US infra.
    impact_rating = ImpactRating(privacy=1.5, security=3.0, resilience=2.5)
    impact_notes = {
        "privacy": "The container itself ships little, but reveals the "
            "tagging setup; the trackers it loads are scored separately.",
        "security": "Its purpose is to load further third-party code into "
            "your origin — a single mis-set tag, or a GTM compromise, can "
            "run anything as your site.",
        "resilience": "A US-hosted control layer over what executes on "
            "your pages.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key,
                (CAT_OTHER, "Unrecognized GTM parameter", IMPACT_LOW),
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
