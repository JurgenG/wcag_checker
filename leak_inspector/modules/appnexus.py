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

"""AppNexus / Xandr ad-exchange detector.

AppNexus (acquired by AT&T in 2018, re-branded Xandr, then acquired by
Microsoft in 2022) operates one of the largest programmatic ad
exchanges.
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


_HOST_SUFFIX = ".adnxs.com"
_HOST_EXACT = "adnxs.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "uid":       (CAT_IDENTIFIER, "AppNexus / Xandr visitor pseudonym (``uuid2`` cookie value)", IMPACT_HIGH),
    "pub_id":    (CAT_TECHNICAL,  "Publisher account ID",                       IMPACT_LOW),
    "seller_id": (CAT_TECHNICAL,  "SSP seller ID",                              IMPACT_LOW),
    "bidder":    (CAT_TECHNICAL,  "Bidder identifier (prebid cookie-sync)",     IMPACT_LOW),
    "tag_id":    (CAT_TECHNICAL,  "Ad-tag / placement ID",                      IMPACT_LOW),
    "e":  (CAT_BEHAVIORAL, "Opaque encoded event payload",                      IMPACT_MEDIUM),
    "pl": (CAT_TECHNICAL,  "Platform / OS (observed value: ``linux``)",         IMPACT_LOW),
    "ua": (CAT_TECHNICAL,  "Browser-engine identifier (observed: ``gecko40``)", IMPACT_LOW),
    "tv": (CAT_TECHNICAL,  "AppNexus tag identifier (observed: ``view7-28hs``; ``view7`` family suggests viewability tag, exact semantics undocumented)", IMPACT_LOW),
    "vd": (CAT_BEHAVIORAL, "Structured viewability-state codes (observed forms: ``ct~0|rr~<n>|dm~<n>``; semantics undocumented)", IMPACT_LOW),
    "ww": (CAT_TECHNICAL, "Window viewport width (px)",                         IMPACT_LOW),
    "wh": (CAT_TECHNICAL, "Window viewport height (px)",                        IMPACT_LOW),
    "sw": (CAT_TECHNICAL, "Screen width (px)",                                  IMPACT_LOW),
    "sh": (CAT_TECHNICAL, "Screen height (px)",                                 IMPACT_LOW),
    "ph": (CAT_TECHNICAL, "Page height (px)",                                   IMPACT_LOW),
    "referrer": (CAT_CONTENT, "Page URL the impression rendered on",            IMPACT_MEDIUM),
    "bdref":    (CAT_CONTENT, "Bid-redirect referrer URL",                      IMPACT_MEDIUM),
    "bdtop":    (CAT_CONTENT, "Top-frame URL",                                  IMPACT_MEDIUM),
    "bstk":     (CAT_CONTENT, "Frame URL back-stack (comma-separated)",         IMPACT_MEDIUM),
    "an_audit": (CAT_TECHNICAL, "AppNexus audit-mode flag",                     IMPACT_LOW),
    "s":        (CAT_TECHNICAL, "Request signature (40-char hex, observed)",    IMPACT_LOW),
    "cbfn":     (CAT_TECHNICAL, "JSONP callback function name",                 IMPACT_LOW),
    "gdpr":          (CAT_CONSENT, "IAB TCF: GDPR-applies flag",                IMPACT_LOW),
    "gdpr_consent":  (CAT_CONSENT, "IAB TCF consent string",                    IMPACT_LOW),
    "gpp":           (CAT_CONSENT, "IAB Global Privacy Platform string",        IMPACT_LOW),
    "gpp_sid":       (CAT_CONSENT, "IAB GPP section IDs",                       IMPACT_LOW),
    "addtl_consent": (CAT_CONSENT, "IAB Additional-Consent string (AC v2)",     IMPACT_LOW),
    "google_cver":   (CAT_CONSENT, "Google consent / cookie-sync version",      IMPACT_LOW),
}


@register
class AppNexusModule(TrackerModule):
    """Detect AppNexus / Xandr prebid, viewability, and cookie-sync traffic."""

    module_id = "appnexus"
    module_name = "AppNexus / Xandr"
    vendor = "Microsoft Corporation (Xandr, formerly AppNexus / AT&T)"
    legal_jurisdiction = "US"
    data_residency = "Global serving infrastructure (regional ``<region>-ib.adnxs.com`` endpoints)"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # privacy 4.0: programmatic exchange joining the visit to a web-wide
    #   ad profile, cross-site by design. security 4.0: OpenRTB +
    #   cookie-sync chains redirect to demand partners the operator
    #   cannot enumerate (rubric security 4.0, transitive fourth parties).
    #   resilience 2.5: US, ad-revenue supporting feature, one of many
    #   replaceable bidders (rubric 2.5).
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=2.5)
    impact_notes = {
        "privacy": "A programmatic ad exchange that joins this visit to a "
            "web-wide advertising profile — cross-site by design.",
        "security": "OpenRTB auctions and cookie-sync chains redirect the "
            "visitor into demand partners you cannot enumerate.",
        "resilience": "A US ad-revenue dependency — one of many "
            "replaceable bidders, but foreign-controlled.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized AppNexus parameter", IMPACT_LOW)
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
