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

"""The Trade Desk detector.

The Trade Desk (TTD) operates one of the largest independent demand-
side platforms (DSPs). Its cookie-match endpoints fire from
publisher pages as part of the open-RTB programmatic chain, syncing
the publisher's first-party cookie space against the TTD identity
graph (and onward to DMPs / SSPs).

Recognized hosts: ``*.adsrvr.org`` (the TTD-owned ad-serving family —
``match.adsrvr.org``, ``insight.adsrvr.org``, etc.). Notable paths:

* ``/track/cmf/generic`` and ``/track/cmf/<partner>`` — cookie-match
  endpoints triggered when a publisher's page wants TTD to mint or
  read its persistent visitor ID.
* ``/track/up`` — Universal Pixel, the advertiser-served conversion
  / audience-membership beacon.
* ``/track/rmb/`` — remarketing bid hook.

The visitor pseudonym is HIGH-impact (one persistent ad-tech ID that
unlocks cross-site behavioral targeting); ``gdpr_consent`` is the
TCF consent string. Other fields are best-effort labeled from TTD's
public documentation.
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


_HOST_SUFFIX = ".adsrvr.org"
_HOST_EXACT = "adsrvr.org"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "ttd_pid":  (CAT_TECHNICAL,  "TTD partner ID (which integration is calling)", IMPACT_LOW),
    "adv":      (CAT_TECHNICAL,  "Advertiser ID (TTD seat)",                      IMPACT_LOW),
    "vrid":     (CAT_IDENTIFIER, "Visitor reference ID (TTD-side pseudonym)",     IMPACT_HIGH),
    "uid":      (CAT_IDENTIFIER, "Partner-supplied user ID",                      IMPACT_HIGH),
    "ev":       (CAT_BEHAVIORAL, "Event name (pageview, conversion, …)",          IMPACT_MEDIUM),
    "n":        (CAT_BEHAVIORAL, "Event name (alt form)",                          IMPACT_MEDIUM),
    "td1":      (CAT_BEHAVIORAL, "Advertiser custom data slot 1",                 IMPACT_MEDIUM),
    "td2":      (CAT_BEHAVIORAL, "Advertiser custom data slot 2",                 IMPACT_MEDIUM),
    "td3":      (CAT_BEHAVIORAL, "Advertiser custom data slot 3",                 IMPACT_MEDIUM),
    "td4":      (CAT_BEHAVIORAL, "Advertiser custom data slot 4",                 IMPACT_MEDIUM),
    "td5":      (CAT_BEHAVIORAL, "Advertiser custom data slot 5",                 IMPACT_MEDIUM),
    "domain":   (CAT_CONTENT, "Publisher domain firing the pixel",                IMPACT_LOW),
    "r":        (CAT_CONTENT, "Redirect-chain target (next vendor in ID-sync hop)", IMPACT_MEDIUM),
    "gdpr":         (CAT_CONSENT, "GDPR-applies flag (0/1)",                       IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "IAB TCF consent string",                        IMPACT_LOW),
    "us_privacy":   (CAT_CONSENT, "IAB CCPA US-privacy string",                    IMPACT_LOW),
    "v":        (CAT_TECHNICAL, "Pixel protocol version",                          IMPACT_LOW),
    "nh":       (CAT_TECHNICAL, "No-HTML / no-redirect flag",                      IMPACT_LOW),
}


@register
class TradeDeskModule(TrackerModule):
    """Detect The Trade Desk DSP cookie-match and universal-pixel traffic."""

    module_id = "trade_desk"
    module_name = "The Trade Desk"
    vendor = "The Trade Desk, Inc."
    legal_jurisdiction = "US"
    data_residency = "US (Ventura, CA HQ); global serving infrastructure"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # DSP + UID2 identity: privacy 4.0 (cross-site, the UID2 graph;
    #   UID2-from-hashed-email could reach 5.0 as a Phase-5 variant when
    #   observed). security 4.0 (bidstream + sync chain — rubric 4.0).
    #   resilience 2.5 (US, replaceable demand source — rubric 2.5).
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=2.5)
    impact_notes = {
        "privacy": "A DSP joining this visit to a web-wide profile via "
            "the UID2 identity graph — cross-site by design.",
        "security": "Bidstream and a sync chain redirect the visitor into "
            "partners you cannot enumerate.",
        "resilience": "A US demand-side dependency, replaceable but "
            "foreign-controlled.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Trade Desk parameter", IMPACT_LOW)
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
