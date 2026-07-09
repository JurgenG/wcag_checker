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

"""Ezoic publisher-monetization detector.

Ezoic Inc. (US, Carlsbad CA) operates a publisher-monetization stack
deployed on independent publishers (news, niche blogs). Observed host
fingerprint across three hosts that always co-load on Ezoic-monetized
pages:

* ``g.ezoic.net`` — primary beacon / config / pixel host. Serves the
  whimsical-city-name path family (``/detroitchicago/<n>.js``,
  ``/parsonsmaize/<n>.js``, ``/porpoiseant/<n>.js``,
  ``/tardisrocinante/<n>.js``) that's diagnostic of Ezoic, plus
  ``/ez-vasts``, ``/saa.go`` (Smart Auction), ``/cmp/log.gif`` (CMP),
  ``/ezais/analytics``, ``/ezintegration``, ``/ezoic/ezoiclitedata.go``.
  Sets ``ezoid`` (1-year HttpOnly visitor pseudonym) and
  ``ezfs_<publisher_id>`` (publisher-domain-scoped session ID).
* ``go.ezodn.com`` — JS asset host. Same city-name path scheme,
  plus explicit ``/ezoicanalytics.js`` and ``/ezoic/ezorca.min.js``.
* ``qvdt3feo.com`` — **shadow domain** Ezoic uses to forward visitor
  identifiers into Google's ad graph. Carries ``google_push`` /
  ``google_gid`` / ``google_cver`` tokens on ``/sync``; sets
  ``sa-user-id`` / ``sa-user-id-v2`` (1-year ``Max-Age``) — the
  Smart Auction visitor pseudonym, scoped to the shadow domain to
  evade tracker blocklists.

We claim the shadow domain by exact host match. It may rotate; the
two stable Ezoic-branded hosts give independent confidence even when
the shadow rotates.

Sovereignty: US controller, CLOUD Act applies. The distinctive
privacy story is the **shadow-domain cookie-sync into Google**: even
without a direct Google tag on the page, Ezoic forwards the visitor
graph to ``cm.g.doubleclick.net`` server-side via ``qvdt3feo.com``.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
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


_HOST_SUFFIXES: tuple[str, ...] = (".ezoic.net", ".ezodn.com")
_HOST_EXACT: frozenset[str] = frozenset({
    "ezoic.net",
    "ezodn.com",
    #: Observed shadow domain used for the Google cookie-sync forward.
    #: May rotate; the two ``.ezoic.net`` / ``.ezodn.com`` hosts provide
    #: independent confidence.
    "qvdt3feo.com",
})


_PARAMS: dict[str, tuple[str, str, str]] = {
    # --- Ezoic-side identifiers ---
    "did":      (CAT_TECHNICAL, "Ezoic publisher / domain ID", IMPACT_LOW),
    "dId":      (CAT_TECHNICAL, "Ezoic domain ID (CMP-endpoint spelling)", IMPACT_LOW),
    "dcId":     (CAT_TECHNICAL, "Ezoic domain config ID", IMPACT_LOW),
    "pid":      (CAT_IDENTIFIER, "Page / placement ID (UUID per page instance)", IMPACT_MEDIUM),
    "nid":      (CAT_TECHNICAL, "Sync partner / network ID", IMPACT_LOW),
    # --- forwarded Google sync tokens (HIGH — these are Google's cross-graph IDs) ---
    "google_gid":  (CAT_IDENTIFIER, "Google cookie-sync graph ID being forwarded into Google's DSP", IMPACT_HIGH),
    "google_push": (CAT_IDENTIFIER, "Google cookie-sync push payload (encrypted visitor mapping)", IMPACT_HIGH),
    "google_cver": (CAT_IDENTIFIER, "Google cookie-sync version tag", IMPACT_HIGH),
    "google_nid":  (CAT_IDENTIFIER, "Google network ID used during sync", IMPACT_HIGH),
    "google_hm":   (CAT_IDENTIFIER, "Google hashed-match identifier", IMPACT_HIGH),
    # --- page context (URL leak) ---
    "url":     (CAT_CONTENT, "Visited-page URL", IMPACT_MEDIUM),
    "ref":     (CAT_CONTENT, "Document referrer URL", IMPACT_MEDIUM),
    "d":       (CAT_CONTENT, "Domain / page being measured", IMPACT_LOW),
    "orig":    (CAT_CONTENT, "Origin / publisher host", IMPACT_LOW),
    "redirect": (CAT_CONTENT, "Downstream redirect target (cookie-sync chain)", IMPACT_MEDIUM),
    # --- consent signals ---
    "gdpr":          (CAT_CONSENT, "GDPR applicability flag (1 = TCF v2.2 applies)", IMPACT_LOW),
    "gdpr_consent":  (CAT_CONSENT, "IAB TCF v2.2 consent string", IMPACT_LOW),
    "gpp":           (CAT_CONSENT, "IAB Global Privacy Platform string", IMPACT_LOW),
    "gpp_sid":       (CAT_CONSENT, "GPP section ID(s)", IMPACT_LOW),
    "us_privacy":    (CAT_CONSENT, "IAB US Privacy (CCPA) signal", IMPACT_LOW),
    "consentV2":     (CAT_CONSENT, "Ezoic CMP consent string (v2 — TCF-shaped)", IMPACT_LOW),
    "buttonId":      (CAT_CONSENT, "CMP button click ID (accept / reject / customize)", IMPACT_LOW),
    # --- technical / cache-busters / opaque internals ---
    "cb":      (CAT_TECHNICAL, "Cache-buster", IMPACT_LOW),
    "gcb":     (CAT_TECHNICAL, "Global cache-buster (build-tag)", IMPACT_LOW),
    "dcb":     (CAT_TECHNICAL, "Domain cache-buster", IMPACT_LOW),
    "shcb":    (CAT_TECHNICAL, "Shared cache-buster", IMPACT_LOW),
    "wc":      (CAT_TECHNICAL, "Window / viewport metric (observed integer)", IMPACT_LOW),
    "npv":     (CAT_TECHNICAL, "Non-personalized-view flag", IMPACT_LOW),
    "ts":      (CAT_TECHNICAL, "Hit client timestamp", IMPACT_LOW),
    "sts":     (CAT_TECHNICAL, "Session / sequence timestamp", IMPACT_LOW),
    "version": (CAT_TECHNICAL, "CMP / SDK version", IMPACT_LOW),
    "v":       (CAT_TECHNICAL, "Pixel version", IMPACT_LOW),
    "ds":      (CAT_TECHNICAL, "Opaque Ezoic internal flag", IMPACT_LOW),
    "a":       (CAT_TECHNICAL, "Opaque Ezoic internal flag", IMPACT_LOW),
    "e":       (CAT_TECHNICAL, "Opaque event payload tag", IMPACT_LOW),
}


@register
class EzoicModule(TrackerModule):
    """Detect Ezoic publisher-monetization beacons, loaders and shadow syncs."""

    module_id = "ezoic"
    module_name = "Ezoic"
    vendor = "Ezoic Inc."
    legal_jurisdiction = "US"
    data_residency = (
        "Ezoic-operated infrastructure (Carlsbad CA + AWS/GCP, US-region "
        "primary) with documented forwarding into Google's ad graph via "
        "the qvdt3feo.com shadow domain."
    )
    sovereignty_notes = (
        "US controller — CLOUD Act and FISA 702 apply. The distinctive "
        "Ezoic privacy story is the shadow-domain (``qvdt3feo.com``) "
        "cookie-sync that forwards visitor identifiers into Google's ad "
        "graph (cm.g.doubleclick.net) server-side. Even without a "
        "direct Google tag on the page, Ezoic-monetized sites surface "
        "their audience to Google via this path, compounding Schrems II "
        "exposure for EU visitors."
    )
    # Publisher-monetization stack: privacy 4.0 (cross-site ad audience +
    #   the shadow-domain sync forwarding IDs into Google's graph).
    #   security 4.0: an ad-mediation layer loading many demand partners —
    #   transitive fourth parties (rubric 4.0). resilience 3.0: US
    #   monetization platform with real lock-in for the publishers it
    #   serves (rubric 3.0; higher when run in full reverse-proxy mode,
    #   which this module can't certify — certainty rule).
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=3.0)
    impact_notes = {
        "privacy": "A monetization stack that joins the visit to an ad "
            "audience, plus a shadow-domain sync forwarding IDs into "
            "Google's graph.",
        "security": "An ad-mediation layer loading many demand partners — "
            "transitive fourth parties you cannot enumerate.",
        "resilience": "A US monetization platform with real lock-in for "
            "the publishers it serves.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _HOST_EXACT:
            return True
        return any(host.endswith(suffix) for suffix in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Ezoic parameter", IMPACT_LOW)
            )
            params.append(ParamInfo(
                key=key,
                value=value,
                category=category,
                meaning=meaning,
                privacy_impact=impact,
                event_index=event.event_id,
            ))
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
