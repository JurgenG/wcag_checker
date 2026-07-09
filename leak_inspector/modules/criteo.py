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

"""Criteo retargeting + SSP / cookie-sync detector.

Criteo S.A. (France) operates a multi-host federated stack that
combines a Prebid header-bidding endpoint, a user-sync hub, a display
cookie-sync dispatcher, and an SSP-side sync family. Observed host
fingerprint:

* ``grid-bidder.criteo.com`` — Prebid header-bidding endpoint
  (``/openrtb_2_5/pbjs/auction/request``); OpenRTB JSON body.
* ``gum.criteo.com`` — primary user-sync hub
  (``/sid/json``, ``/syncframe``).
* ``dis.criteo.com`` / ``dis.eu.criteo.com`` — display cookie sync
  dispatcher (``/dis/usersync.aspx``). The ``url=`` query carries the
  downstream partner pixel with a literal ``@@CRITEO_USERID@@``
  placeholder Criteo substitutes server-side.
* ``ssp-sync.criteo.com`` — SSP-side user-sync family
  (``/user-sync/match``, ``/user-sync/redirect``, ``/user-sync/iframe``,
  ``/user-sync/bidder-initiated``).
* ``ag.gbc.criteo.com`` / ``gem.gbc.criteo.com`` — additional sync
  infrastructure (``/newidsd``).
* ``static.criteo.net`` — publisher tag JS
  (``/js/ld/publishertag.ids.js``).

We claim the host family by suffix, not by path — Criteo runs many
related endpoints under these hosts and a host match alone is a
high-confidence signal. Path-only matching would over-claim.

CNIL has repeatedly enforced against Criteo's tracking practices
(notably the €40M fine in 2023). Sovereignty notes reflect Criteo's
French / EU posture: GDPR applies directly with primary CNIL
jurisdiction, but the SSP graph routinely synchronises pseudonyms
into non-EU partners (Google DoubleClick, ID5, Magnite, ContextWeb,
Adform, etc.), which the report can surface via the partner
identifiers Criteo carries on its sync URLs.
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


#: Criteo's host family. The first two registrable domains are owned by
#: Criteo S.A. directly; ``dnsdelegation.io`` and ``storetail.io`` are
#: Criteo's documented CNAME-cloaking delegation domains (NextDNS
#: cname-cloaking blocklist) — first-party-looking subdomains CNAME to
#: them, and matching them here lets the cloak detector attribute the
#: chain's canonical tail to Criteo.
_HOST_SUFFIXES: tuple[str, ...] = (
    ".criteo.com", ".criteo.net", ".dnsdelegation.io", ".storetail.io",
)
_HOST_EXACT: frozenset[str] = frozenset({
    "criteo.com", "criteo.net", "dnsdelegation.io", "storetail.io",
})


_PARAMS: dict[str, tuple[str, str, str]] = {
    # --- visitor / partner identifiers ---
    "u":            (CAT_IDENTIFIER, "Partner-supplied user pseudonym (the ID being linked into Criteo's graph)", IMPACT_HIGH),
    "puid":         (CAT_IDENTIFIER, "Partner user ID (downstream sync target)", IMPACT_HIGH),
    "buyer_id":     (CAT_IDENTIFIER, "Buyer-side user identifier", IMPACT_HIGH),
    "publisher_user_id": (CAT_IDENTIFIER, "Publisher-supplied user identifier", IMPACT_HIGH),
    "profileId":    (CAT_TECHNICAL,  "Publisher / Prebid profile ID", IMPACT_LOW),
    "networkId":    (CAT_TECHNICAL,  "Network ID (publisher network in Criteo's account hierarchy)", IMPACT_LOW),
    "p":            (CAT_IDENTIFIER, "Partner / payload identifier (sync routing tag, often base64)", IMPACT_MEDIUM),
    "cp":           (CAT_TECHNICAL,  "Cookie-sync partner name (e.g. ``google``, ``id5``, ``rubicon``)", IMPACT_LOW),
    "dsp":          (CAT_TECHNICAL,  "Demand-side platform identifier", IMPACT_LOW),
    "bundle":       (CAT_TECHNICAL,  "Site / app bundle identifier", IMPACT_LOW),
    # --- page context ---
    "topUrl":       (CAT_CONTENT,    "Top-frame page URL (full URL of the visited page)", IMPACT_MEDIUM),
    "domain":       (CAT_CONTENT,    "Top-frame host", IMPACT_LOW),
    "url":          (CAT_CONTENT,    "Downstream sync target URL (carries ``@@CRITEO_USERID@@`` placeholder)", IMPACT_MEDIUM),
    "publisher_redirecturl": (CAT_CONTENT, "Publisher-provided redirect target for cookie-sync chains", IMPACT_MEDIUM),
    "origin":       (CAT_CONTENT,    "Sync-origin tag (``prebid`` / ``publishertagids`` / ...)", IMPACT_LOW),
    # --- consent signals ---
    "gdpr":         (CAT_CONSENT,    "GDPR applicability flag (1 = TCF v2.2 applies)", IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT,    "IAB TCF v2.2 consent string", IMPACT_LOW),
    "gdprapplies":  (CAT_CONSENT,    "GDPR-applies flag (legacy spelling)", IMPACT_LOW),
    "gdprString":   (CAT_CONSENT,    "IAB TCF v2.2 consent string (legacy spelling)", IMPACT_LOW),
    "gpp":          (CAT_CONSENT,    "IAB Global Privacy Platform string", IMPACT_LOW),
    "gpp_sid":      (CAT_CONSENT,    "GPP section ID(s)", IMPACT_LOW),
    "us_privacy":   (CAT_CONSENT,    "IAB US Privacy (CCPA) signal", IMPACT_LOW),
    # --- routing / sync flow ---
    "r":            (CAT_TECHNICAL,  "Sync routing code (partner-specific)", IMPACT_LOW),
    "cu":           (CAT_TECHNICAL,  "Cookie-sync update flag", IMPACT_LOW),
    "cw":           (CAT_TECHNICAL,  "Cookie writability probe (1 = cookies allowed)", IMPACT_LOW),
    "lsw":          (CAT_TECHNICAL,  "LocalStorage writability probe (1 = storage allowed)", IMPACT_LOW),
    "lsavail":      (CAT_TECHNICAL,  "LocalStorage-availability probe", IMPACT_LOW),
    "gzip":         (CAT_TECHNICAL,  "Gzip-acceptance hint", IMPACT_LOW),
    # --- versioning / opaque internals ---
    "av":           (CAT_TECHNICAL,  "Criteo asset version", IMPACT_LOW),
    "wv":           (CAT_TECHNICAL,  "Criteo wrapper version", IMPACT_LOW),
    "cb":           (CAT_TECHNICAL,  "Cache-buster", IMPACT_LOW),
    "info":         (CAT_TECHNICAL,  "Opaque Criteo internal info field", IMPACT_LOW),
    # --- OpenRTB envelope fields surfaced to query/body ---
    "imp":          (CAT_BEHAVIORAL, "OpenRTB impression array (placements, sizes, floors)", IMPACT_MEDIUM),
    "site":         (CAT_CONTENT,    "OpenRTB site object (domain, name, content categories)", IMPACT_MEDIUM),
    "user":         (CAT_IDENTIFIER, "OpenRTB user object (visitor pseudonyms, EIDs)", IMPACT_HIGH),
    "device":       (CAT_TECHNICAL,  "OpenRTB device object (UA, IP, geo, screen)", IMPACT_MEDIUM),
    "regs":         (CAT_CONSENT,    "OpenRTB regulatory object (GDPR / COPPA / GPP)", IMPACT_LOW),
}


@register
class CriteoModule(TrackerModule):
    """Detect Criteo retargeting / SSP / cookie-sync requests."""

    module_id = "criteo"
    module_name = "Criteo"
    vendor = "Criteo S.A."
    legal_jurisdiction = "FR"
    data_residency = (
        "Criteo-operated infrastructure (primary EU presence) with "
        "documented cookie-syncs to non-EU partners (Google DoubleClick, "
        "ID5, Magnite, ContextWeb, Adform, etc.)"
    )
    sovereignty_notes = (
        "Criteo S.A. is France-based — CNIL is the lead supervisory "
        "authority (€40M CNIL fine, 2023). GDPR applies directly. "
        "However, the SSP graph routinely synchronises visitor "
        "pseudonyms into non-EU partners, so an EU-controller status "
        "does not preclude downstream Schrems II exposure via the "
        "partner chain Criteo carries on its sync URLs."
    )
    # privacy 4.0: retargeting + user-sync hub joining the visitor to a
    #   web-wide ad profile, cross-site by design (rubric privacy 4.0).
    # security 4.0: runs OpenRTB auctions + a cookie-sync hub
    #   (gum.criteo.com) that redirects pseudonyms into partners the
    #   operator cannot enumerate — the rubric's transitive-fourth-parties
    #   line (security 4.0). resilience 1.5: Criteo S.A. is EU (France),
    #   GDPR-native — an EU ad vendor with switching costs (rubric 1.5),
    #   despite the non-EU downstream sync (that's a privacy/security
    #   concern, already counted, not a sovereignty-of-the-vendor one).
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=1.5)
    impact_notes = {
        "privacy": "A retargeting + user-sync hub that joins this visit to "
            "a web-wide advertising profile.",
        "security": "Runs OpenRTB auctions and a cookie-sync hub that "
            "redirects the visitor's pseudonym into demand partners you "
            "cannot enumerate.",
        "resilience": "An EU vendor (France), but the downstream sync "
            "still reaches non-EU partners.",
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
                key, (CAT_OTHER, "Unrecognized Criteo parameter", IMPACT_LOW)
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
