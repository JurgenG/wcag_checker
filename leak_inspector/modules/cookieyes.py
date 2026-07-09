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

"""CookieYes Consent Management Platform detector.

CookieYes (operated by CookieYes Limited, UK) is a CMP encountered in the
municipalities captures. Its banner SDK loads per-site from
``cdn-cookieyes.com/client_data/<client-id>/script.js`` — the per-site
identifier rides in the path, so it shows in the representative-hit URL
rather than the query string. The CookieYes app / consent-log endpoints
live under ``cookieyes.com``.

CookieYes persists its decision in a first-party ``cookieyes-consent``
cookie, but no decodable artifact was captured, so this module only
*names* the banner — the consent state stays ``"unknown"``, like the
TrustArc / Sourcepoint detectors. Its module ID is registered in
``analysis.consent._CMP_MODULE_IDS`` so a CookieYes beacon firing before
the visitor's choice is not mistaken for a pre-consent tracking offender.
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


#: Registrable domains CookieYes serves from. The banner CDN lives on its
#: own ``cdn-cookieyes.com`` registrable domain (not a subdomain of
#: ``cookieyes.com``), so both are matched, each including subdomains.
_DOMAINS: tuple[str, ...] = ("cookieyes.com", "cdn-cookieyes.com")


@register
class CookieYesModule(TrackerModule):
    """Detect CookieYes CMP banner / consent-log requests."""

    module_id = "cookieyes"
    module_name = "CookieYes"
    vendor = "CookieYes Limited"
    legal_jurisdiction = "UK"
    data_residency = "UK"
    sovereignty_notes = ""
    # Third-party CMP, UK: privacy 1.5 / security 2.5 / resilience 1.5
    # (UK is non-EU adequacy — rubric 1.5, above the EU CMPs' 1.0). See
    # cookiebot for the shared shape.
    impact_rating = ImpactRating(privacy=1.5, security=2.5, resilience=1.5)
    impact_notes = {
        "privacy": "A consent record plus presence telemetry at a "
            "third-party CMP.",
        "security": "Loads an unpinned CMP script into your origin.",
        "resilience": "UK-based — a non-EU adequacy jurisdiction.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return any(host == d or host.endswith("." + d) for d in _DOMAINS)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            params.append(
                ParamInfo(
                    key=key,
                    value=value,
                    category=CAT_OTHER,
                    meaning="Unrecognized CookieYes parameter",
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
