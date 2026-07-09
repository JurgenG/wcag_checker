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

"""Adobe Helix RUM (Real User Monitoring) detector.

Adobe Helix RUM is the Real-User-Monitoring component of Adobe's open-
source `Edge Delivery Services <https://www.aem.live>`_ (formerly
Project Helix). The JavaScript SDK at ``rum.hlx.page/.rum/@adobe/helix-
rum-js`` collects anonymized page-load / interaction timing and reports
it back to ``rum.hlx.page`` via beacon POSTs.

Recognized host: ``rum.hlx.page``.

What's known to be collected (per the project's public documentation):
page-view counters, navigation-timing data, content-element click/view
samples, an anonymous per-visit checksum. The project's docs emphasize
that **no per-visitor identifier is set** — it samples client behaviour
without setting a persistent cookie. That stance hasn't been verified
against captured beacon traffic here.

In the bundle that exercised this module, only the SDK script
(``/.rum/@adobe/helix-rum-js@^2/dist/micro.js``) was fetched — no
beacon POSTs were observed. This module recognizes the host so the
SDK loader stops appearing in the unmatched-third-party section; any
future beacon traffic captured against this host will surface with
its raw parameters (no param dictionary is hardcoded since none has
been evidenced).
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_OTHER,
    Hit,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_EXACT = "rum.hlx.page"


@register
class AdobeHelixRumModule(TrackerModule):
    """Detect Adobe Helix RUM (Real User Monitoring) SDK + beacon traffic."""

    module_id = "adobe_helix_rum"
    module_name = "Adobe Helix RUM"
    vendor = "Adobe Inc."
    legal_jurisdiction = "US"
    data_residency = "Adobe-operated CDN (open-source project; same residency profile as Adobe Edge Delivery Services)"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # RUM (sampled, privacy-conscious): privacy 1.5 (aggregate technical
    #   telemetry; rubric 1.5). security 2.0 (unpinned but narrow RUM
    #   snippet). resilience 2.0 (US Adobe, replaceable — rubric 2.0).
    impact_rating = ImpactRating(privacy=1.5, security=2.0, resilience=2.0)
    impact_notes = {
        "privacy": "Sampled real-user-monitoring telemetry — aggregate, "
            "no durable visitor profile.",
        "security": "Loads an unpinned but narrow RUM snippet into your "
            "origin.",
        "resilience": "A US (Adobe) RUM dependency — replaceable.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return event.host.lower() == _HOST_EXACT

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            params.append(
                ParamInfo(
                    key=key,
                    value=value,
                    category=CAT_OTHER,
                    meaning="Unrecognized Adobe Helix RUM parameter",
                    privacy_impact=IMPACT_LOW,
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
