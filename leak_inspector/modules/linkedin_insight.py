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

"""LinkedIn Insight Tag detector.

Recognizes:

* ``px.ads.linkedin.com`` — the Insight Tag pixel endpoint. Carries the
  partner (advertiser) ID, conversion event, page URL, and the
  persistent ``liUuid`` visitor pseudonym.
* ``www.linkedin.com/li/track`` and similar ``/li/`` paths — alternative
  tracking endpoints sometimes fired from LinkedIn-owned pages.
* ``snap.licdn.com`` — the JS loader CDN (``insight.min.js`` etc.).

When the visitor is signed into LinkedIn, the request often carries
their member ID directly (``mid``) and a logged-in indicator — those
are treated as PII rather than mere identifiers.
"""

from __future__ import annotations

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


_PIXEL_HOST = "px.ads.linkedin.com"
_LOADER_HOST = "snap.licdn.com"
_LI_HOST_SUFFIX = ".linkedin.com"
_LI_HOST_EXACT = "linkedin.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "pid":           (CAT_TECHNICAL,  "Partner (advertiser) ID — the customer's tracking key", IMPACT_LOW),
    "liS_pid":       (CAT_TECHNICAL,  "Partner ID (alternate form)",            IMPACT_LOW),
    "liUuid":        (CAT_IDENTIFIER, "Persistent LinkedIn visitor UUID",       IMPACT_HIGH),
    "liUuidHashed":  (CAT_IDENTIFIER, "Hashed visitor UUID",                    IMPACT_HIGH),
    "conversionId":  (CAT_BEHAVIORAL, "Conversion event ID",                    IMPACT_MEDIUM),
    "mid":          (CAT_PII, "LinkedIn member ID (set when the visitor is signed in)", IMPACT_HIGH),
    "isLoggedIn":   (CAT_PII, "Logged-in flag — reveals whether the visitor has a LinkedIn session", IMPACT_MEDIUM),
    "e": (CAT_BEHAVIORAL, "Event type",                                         IMPACT_MEDIUM),
    "ec": (CAT_TECHNICAL, "Event count",                                        IMPACT_LOW),
    "tagMethod": (CAT_TECHNICAL, "How the tag was fired (auto / manual / GTM)", IMPACT_LOW),
    "url": (CAT_CONTENT, "Page URL the tag fired on",                           IMPACT_MEDIUM),
    "referrer": (CAT_CONTENT, "Document referrer",                              IMPACT_MEDIUM),
    "fmt":   (CAT_TECHNICAL, "Response format (e.g. ``gif`` = 1×1 pixel)",      IMPACT_LOW),
    "time":  (CAT_TECHNICAL, "Client-side timestamp",                           IMPACT_LOW),
    "gen":   (CAT_TECHNICAL, "Tag generation / library version",                IMPACT_LOW),
    "v":     (CAT_TECHNICAL, "Tag protocol version",                            IMPACT_LOW),
    "_tn_":  (CAT_TECHNICAL, "Tracking name (internal LinkedIn dispatch)",      IMPACT_LOW),
    "gdprApplies":  (CAT_CONSENT, "GDPR-applies flag",                          IMPACT_LOW),
    "gdprConsent":  (CAT_CONSENT, "TCF consent string",                         IMPACT_LOW),
    "medium":       (CAT_TECHNICAL,  "JS dispatch method (observed: ``fetch``)", IMPACT_LOW),
    "tm":           (CAT_TECHNICAL,  "Tag-manager source (observed: ``gtmv2``)", IMPACT_LOW),
}


@register
class LinkedInInsightModule(TrackerModule):
    """Detect LinkedIn Insight Tag pixel and loader requests."""

    module_id = "linkedin_insight"
    module_name = "LinkedIn Insight Tag"
    vendor = "Microsoft Corporation (LinkedIn)"
    legal_jurisdiction = "US"
    data_residency = "Microsoft global infrastructure"
    sovereignty_notes = "US CLOUD Act applies"
    # privacy 4.0: persistent liUuid pseudonym + reporting to LinkedIn's
    #   ad network for retargeting/conversion, joinable to the member
    #   graph — cross-site tracking by design (rubric privacy 4.0).
    # security 2.5: ordinary unpinned tag. resilience 3.0: a foreign
    #   (US/Microsoft) audience layer; B2B outreach rarely load-bearing
    #   for the public-sector corpus, so below Meta's 3.5 (rubric 3.0).
    impact_rating = ImpactRating(privacy=4.0, security=2.5, resilience=3.0)
    impact_notes = {
        "privacy": "Sets a persistent liUuid and reports to LinkedIn for "
            "retargeting/conversion, joinable to the member graph — "
            "cross-site by design.",
        "security": "Loads an unpinned LinkedIn tag into your origin.",
        "resilience": "A US (Microsoft) audience layer the outreach "
            "depends on.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host == _PIXEL_HOST or host == _LOADER_HOST:
            return True
        if host == _LI_HOST_EXACT or host.endswith(_LI_HOST_SUFFIX):
            path = urlparse(event.url).path
            return path.startswith("/li/track") or path.startswith("/li/li.")
        return False

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized LinkedIn Insight parameter", IMPACT_LOW)
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
