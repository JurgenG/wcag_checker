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

"""Index Exchange SSP detector (a.k.a. CasaleMedia).

Index Exchange is a Toronto-headquartered SSP. Its serving
infrastructure remains under the legacy ``casalemedia.com`` domain
(from the pre-rebrand Casale Media era), with newer assets on
``indexexchange.com``.

Recognized hosts: ``*.casalemedia.com`` (incl. ``ssum.casalemedia.com``,
``dsum-sec.casalemedia.com``, ``ssum-sec.casalemedia.com``,
``as-sec.casalemedia.com``) and ``*.indexexchange.com``. Notable paths:

* ``/rum`` — real-user measurement / cookie-sync.
* ``/usermatch.gif`` — image-pixel user-match.
* ``/cm`` — cookie-match endpoint.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_CONSENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_HIGH,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIXES = (".casalemedia.com", ".indexexchange.com")
_HOST_EXACTS = {"casalemedia.com", "indexexchange.com"}


_PARAMS: dict[str, tuple[str, str, str]] = {
    # --- sync targets ---
    "cm_dsp_id":       (CAT_TECHNICAL,  "Index Exchange DSP ID (which buyer is initiating the sync)", IMPACT_LOW),
    "external_user_id": (CAT_IDENTIFIER, "Partner-supplied user ID being synced into IX",             IMPACT_HIGH),
    "partner_uid":     (CAT_IDENTIFIER, "Partner user ID (alt form)",                                  IMPACT_HIGH),
    # --- consent ---
    "gdpr":         (CAT_CONSENT, "GDPR-applies flag (0/1)",                                            IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "IAB TCF consent string",                                             IMPACT_LOW),
    "us_privacy":   (CAT_CONSENT, "IAB CCPA US-privacy string",                                         IMPACT_LOW),
    # --- redirect chain ---
    "r":            (CAT_TECHNICAL, "Redirect target after sync completes",                             IMPACT_LOW),
    "redir":        (CAT_TECHNICAL, "Redirect target (alt form)",                                       IMPACT_LOW),
}


@register
class IndexExchangeModule(TrackerModule):
    """Detect Index Exchange (CasaleMedia) SSP cookie-sync traffic."""

    module_id = "index_exchange"
    module_name = "Index Exchange"
    vendor = "Index Exchange, Inc."
    legal_jurisdiction = "CA"
    data_residency = "Canada (Toronto HQ); US operations through subsidiaries"
    sovereignty_notes = (
        "Canadian PIPEDA primary; US CLOUD Act may reach US-operated infrastructure"
    )
    # SSP: privacy 4.0 (cross-site), security 4.0 (OpenRTB sync chain).
    # resilience 1.5: Index Exchange is Toronto-based — Canada is a
    #   non-EU *adequacy* country (rubric resilience 1.5), so it ranks
    #   above the US SSPs (2.5) but below EU vendors.
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=1.5)
    impact_notes = {
        "privacy": "An SSP that joins this visit to a web-wide "
            "advertising profile — cross-site by design.",
        "security": "OpenRTB auctions and a sync chain redirect the "
            "visitor into demand partners you cannot enumerate.",
        "resilience": "Toronto-based — Canada is a non-EU adequacy "
            "country, so a lighter dependency than the US exchanges.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _HOST_EXACTS:
            return True
        return any(host.endswith(s) for s in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Index Exchange parameter", IMPACT_LOW)
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
