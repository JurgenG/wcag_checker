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

"""Adform SSP / cookie-sync detector.

Adform A/S (Denmark) operates a multi-host cookie-sync + ad exchange
stack. Observed host fingerprint:

* ``c1.adform.net`` — primary cookie-match endpoint
  (``/serving/cookie/match``). Sets the ``uid`` persistent pseudonym
  cookie with a ~3-month ``Expires``, scoped to ``Domain=adform.net``.
* ``cm.adform.net`` — cookie management / consent endpoint
  (``/cookie``).
* ``track.adform.net`` — tracking + sync
  (``/serving/cookie/match/``; the legacy ``/Serving/Cookie/``
  endpoint takes an ``adfaction=getjs;adfcookname=uid``-style
  semicolon-delimited action string).
* ``adx.adform.net`` — OpenRTB ad exchange (``/adx/openrtb``).

GDPR applies directly (Adform is an EU controller), but the SSP graph
synchronises pseudonyms into partners regardless of jurisdiction.
The ``party`` parameter on cookie-match requests names the partner
being synced, so the report can surface the chain.
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


_HOST_SUFFIX = ".adform.net"
_HOST_EXACT = "adform.net"


_PARAMS: dict[str, tuple[str, str, str]] = {
    # --- visitor / partner identifiers ---
    "party":               (CAT_TECHNICAL,  "Cookie-sync partner ID (the partner being matched into Adform's graph)", IMPACT_LOW),
    "cid":                 (CAT_IDENTIFIER, "Partner cookie identifier", IMPACT_MEDIUM),
    "CC":                  (CAT_IDENTIFIER, "Partner cookie identifier (alternate casing)", IMPACT_MEDIUM),
    "buyer_id":            (CAT_IDENTIFIER, "Buyer-side user identifier", IMPACT_HIGH),
    "publisher_user_id":   (CAT_IDENTIFIER, "Publisher-supplied user identifier (often a real account id)", IMPACT_HIGH),
    "publisher_dsp_id":    (CAT_TECHNICAL,  "DSP integration identifier", IMPACT_LOW),
    "publisher_call_type": (CAT_TECHNICAL,  "Publisher-side call-type tag", IMPACT_LOW),
    "dsp_callback":        (CAT_IDENTIFIER, "DSP callback identifier", IMPACT_MEDIUM),
    "piggybackCookie":     (CAT_IDENTIFIER, "Opaque cookie value piggybacked through the redirect chain", IMPACT_MEDIUM),
    # --- redirect / sync chain ---
    "redirect":              (CAT_CONTENT,    "Downstream redirect target", IMPACT_MEDIUM),
    "redirect_url":          (CAT_CONTENT,    "Downstream redirect target (full URL)", IMPACT_MEDIUM),
    "publisher_redirecturl": (CAT_CONTENT,    "Publisher-supplied redirect target for the sync chain", IMPACT_MEDIUM),
    "sspurl":                (CAT_CONTENT,    "SSP-side downstream URL", IMPACT_MEDIUM),
    "callback":              (CAT_CONTENT,    "Sync callback URL", IMPACT_MEDIUM),
    # --- consent signals ---
    "gdpr":         (CAT_CONSENT,    "GDPR applicability flag (1 = TCF v2.2 applies)", IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT,    "IAB TCF v2.2 consent string", IMPACT_LOW),
    "gpp":          (CAT_CONSENT,    "IAB Global Privacy Platform string", IMPACT_LOW),
    "gpp_sid":      (CAT_CONSENT,    "GPP section ID(s)", IMPACT_LOW),
    "us_privacy":   (CAT_CONSENT,    "IAB US Privacy (CCPA) signal", IMPACT_LOW),
    # --- Adform action / control ---
    "adfaction":    (CAT_TECHNICAL,  "Adform action string (e.g. ``getjs;adfcookname=uid``)", IMPACT_LOW),
}


@register
class AdformModule(TrackerModule):
    """Detect Adform SSP / cookie-sync / OpenRTB requests."""

    module_id = "adform"
    module_name = "Adform"
    vendor = "Adform A/S"
    legal_jurisdiction = "DK"
    data_residency = (
        "Adform-operated infrastructure (primary EU presence) with "
        "documented cookie-syncs to non-EU partners (US DSPs, ID5, etc.)"
    )
    sovereignty_notes = (
        "Adform A/S is Denmark-based — EU controller, GDPR applies "
        "directly with the Danish Data Protection Agency as primary "
        "supervisory authority. The SSP graph routinely synchronises "
        "visitor pseudonyms into non-EU partners (named by the "
        "``party`` parameter on cookie-match requests), so an "
        "EU-controller status does not preclude downstream Schrems II "
        "exposure via the partner chain."
    )
    # SSP: privacy 4.0 (cross-site), security 4.0 (cookie-match + sync to
    #   non-EU partners named on the URL — transitive fourth parties).
    # resilience 1.5: Adform A/S is EU (Denmark), GDPR-native — an EU ad
    #   vendor with switching costs (rubric 1.5). The non-EU downstream
    #   sync is a privacy/security concern (counted there), not a
    #   sovereignty-of-the-vendor one.
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=1.5)
    impact_notes = {
        "privacy": "An SSP / cookie-match stack that joins this visit to "
            "a web-wide advertising profile — cross-site by design.",
        "security": "Cookie-match and sync redirect the visitor's "
            "pseudonym into non-EU partners named on the request.",
        "resilience": "An EU vendor (Denmark), GDPR-native — a lighter "
            "dependency than the US exchanges.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Adform parameter", IMPACT_LOW)
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
