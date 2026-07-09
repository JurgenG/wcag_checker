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

"""TrustArc Consent Management Platform detector (formerly TRUSTe).

TrustArc is a US privacy-compliance vendor that delivers a consent
banner, preference center, and per-visitor consent analytics. The
company rebranded from TRUSTe to TrustArc in 2017 — the legacy
``truste.com`` domain still serves the live banner-notice endpoint
alongside the newer ``trustarc.com``, so both are treated as the
same vendor.

Recognized hosts (both surfaces observed live in a KBC capture):

* ``*.trustarc.com`` — banner JS asset (``/asset/notice.js``),
  banner analytics (``/analytics``), modal config
  (``/cm/<domain>/modalconfig``), consent-event log
  (``/consent/log``), and asset CDN (``/get?name=...``).
* ``*.truste.com`` — legacy host preserved primarily for the
  ``/notice`` banner-notice endpoint.

The parameter dictionary below reflects fields observed in captured
traffic, not speculative. Unknown keys fall through to ``CAT_OTHER``.
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
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIXES: tuple[str, ...] = (".trustarc.com", ".truste.com")
_HOST_EXACTS: frozenset[str] = frozenset({"trustarc.com", "truste.com"})


_PARAMS: dict[str, tuple[str, str, str]] = {
    # --- publisher / page context ---
    "domain":   (CAT_CONTENT, "Embedding-site domain (publisher firing the banner)", IMPACT_MEDIUM),
    "referer":  (CAT_CONTENT, "Document referrer (page where the banner loaded)",    IMPACT_MEDIUM),
    # --- identifiers ---
    "session":  (CAT_IDENTIFIER, "Per-visit visitor session pseudonym",              IMPACT_MEDIUM),
    "type":     (CAT_TECHNICAL,  "Per-customer banner template (modalconfig)",       IMPACT_LOW),
    # --- behavioral / event payload ---
    "action":   (CAT_BEHAVIORAL, "Banner-analytics action code (numeric)",           IMPACT_MEDIUM),
    "new":      (CAT_BEHAVIORAL, "New-visitor flag (0/1)",                            IMPACT_LOW),
    # --- consent ---
    "categories": (CAT_CONSENT, "Consent categories accepted by the visitor",        IMPACT_MEDIUM),
    "implied":    (CAT_CONSENT, "Implied-consent flag (0/1)",                         IMPACT_LOW),
    # --- banner configuration / dispatch plumbing ---
    "c":        (CAT_TECHNICAL, "Banner config name (e.g. ``teconsent``)",            IMPACT_LOW),
    "language": (CAT_TECHNICAL, "Banner language",                                   IMPACT_LOW),
    "locale":   (CAT_TECHNICAL, "Banner locale",                                     IMPACT_LOW),
    "country":  (CAT_TECHNICAL, "Visitor country (ISO 2-letter)",                    IMPACT_LOW),
    "layout":   (CAT_TECHNICAL, "Banner layout variant (e.g. ``default_eu``)",       IMPACT_LOW),
    "text":     (CAT_TECHNICAL, "Text-mode flag",                                    IMPACT_LOW),
    "pcookie":  (CAT_TECHNICAL, "Preference-cookie flag",                            IMPACT_LOW),
    "gtm":      (CAT_TECHNICAL, "Loaded-via-GTM flag (0/1)",                          IMPACT_LOW),
    "v":        (CAT_TECHNICAL, "Asset version tag",                                 IMPACT_LOW),
    "name":     (CAT_TECHNICAL, "Asset name (``/get?name=...``)",                    IMPACT_LOW),
}


@register
class TrustArcModule(TrackerModule):
    """Detect TrustArc / TRUSTe banner, analytics, and consent-log traffic."""

    module_id = "trustarc"
    module_name = "TrustArc (formerly TRUSTe)"
    vendor = "TrustArc Inc. (formerly TRUSTe, Inc.)"
    legal_jurisdiction = "US"
    data_residency = "US (San Francisco, CA HQ); global serving infrastructure"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # US third-party CMP: privacy 1.5 (consent record + presence).
    # security 2.5 (unpinned CMP JS, but not the vendor-script
    #   orchestration that lifts OneTrust/Sourcepoint to 3.0). resilience
    #   2.5 (US — rubric 2.5).
    impact_rating = ImpactRating(privacy=1.5, security=2.5, resilience=2.5)
    impact_notes = {
        "privacy": "A consent record plus presence telemetry at a "
            "third-party CMP.",
        "security": "Loads an unpinned CMP script into your origin.",
        "resilience": "A US-controlled consent layer.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _HOST_EXACTS:
            return True
        return any(host.endswith(suffix) for suffix in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized TrustArc parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key,
                    value=value,
                    category=category,
                    meaning=meaning,
                    privacy_impact=impact,
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
