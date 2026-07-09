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

"""PubMatic SSP detector.

PubMatic operates a supply-side platform (SSP) — running header-
bidding auctions on the publisher side and syncing visitor IDs into
its identity graph as part of the open-RTB chain.

Recognized hosts: ``*.pubmatic.com`` (incl. ``image2.pubmatic.com``,
``ads.pubmatic.com``, ``rtb.pubmatic.com``, ``simage2.pubmatic.com``).
Notable paths:

* ``/AdServer/Pug`` — pixel-user-getter, used in cookie-sync hops.
* ``/AdServer/SyncPixel`` — sync-pixel endpoint.
* ``/AdServer/PugMaster`` — master sync orchestrator.
* ``/AdServer/ImgSync`` — image-pixel sync.

The bulk of the cookie-sync payload travels in an opaque
``vcode`` base64 blob, so most of the privacy story is in *the
request itself* (visitor IP, persistent ``KADUSERCOOKIE``) rather
than the URL parameters.
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
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIX = ".pubmatic.com"
_HOST_EXACT = "pubmatic.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "vcode":       (CAT_IDENTIFIER, "Opaque base64 cookie-sync payload (sync targets / partner IDs)", IMPACT_MEDIUM),
    "p":           (CAT_TECHNICAL,  "Publisher / partner ID",                                          IMPACT_LOW),
    "puid":        (CAT_IDENTIFIER, "Partner user ID",                                                 IMPACT_MEDIUM),
    "predirect":   (CAT_TECHNICAL,  "Redirect URL after the sync completes",                           IMPACT_LOW),
    "gdpr":         (CAT_CONSENT, "GDPR-applies flag (0/1)",                                            IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "IAB TCF consent string",                                             IMPACT_LOW),
    "us_privacy":   (CAT_CONSENT, "IAB CCPA US-privacy string",                                         IMPACT_LOW),
    "nc":          (CAT_TECHNICAL, "No-cache cache-buster",                                             IMPACT_LOW),
    "rd":          (CAT_TECHNICAL, "Redirect target",                                                   IMPACT_LOW),
    "ts":          (CAT_TECHNICAL, "Timestamp",                                                         IMPACT_LOW),
}


@register
class PubMaticModule(TrackerModule):
    """Detect PubMatic SSP cookie-sync and pixel traffic."""

    module_id = "pubmatic"
    module_name = "PubMatic"
    vendor = "PubMatic, Inc."
    legal_jurisdiction = "US"
    data_residency = "US (Redwood City, CA HQ); global serving infrastructure"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # SSP: privacy 4.0 (cross-site ad profile), security 4.0 (OpenRTB +
    # sync to transitive demand partners), resilience 2.5 (US, replaceable
    # ad-revenue supporting feature). See appnexus for the shared shape.
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=2.5)
    impact_notes = {
        "privacy": "An SSP that joins this visit to a web-wide "
            "advertising profile — cross-site by design.",
        "security": "OpenRTB auctions and a sync chain redirect the "
            "visitor into demand partners you cannot enumerate.",
        "resilience": "A US ad-revenue dependency, replaceable but "
            "foreign-controlled.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized PubMatic parameter", IMPACT_LOW)
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
