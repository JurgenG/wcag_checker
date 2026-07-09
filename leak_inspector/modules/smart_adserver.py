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

"""Smart AdServer / Equativ ad-server / SSP cookie-sync detector.

Equativ S.A.S. (Paris, France; formerly Smart AdServer, rebranded June
2022) runs an independent ad server and SSP. Its observed footprint is
the cookie-sync endpoints on `csync.smartadserver.com` /
`rtb-csync.smartadserver.com` (`/rtb/csync/CookieSync.html` +
`CookieSync.min.js`, with `nwid` + `dcid`) and `sync.smartadserver.com`
(`/getuid?nwid=…&url=<downstream sync>` with the IAB TCF `gdpr` /
`gdpr_consent` signals), plus the CMP module `cmp.js` on the `*.sascdn.com`
CDN. The `/getuid` `url` parameter 302-redirects the matched id into a
demand partner (e.g. `af.pubmine.com`) — a transitive fourth party.

Recognized hosts: any subdomain of ``smartadserver.com``, ``sascdn.com``,
``equativ.com`` or ``smartadserverapis.com``.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIXES = (
    ".smartadserver.com", ".sascdn.com",
    ".equativ.com", ".smartadserverapis.com",
)
_HOST_EXACT = frozenset({
    "smartadserver.com", "sascdn.com", "equativ.com", "smartadserverapis.com",
})


_PARAMS: dict[str, tuple[str, str, str]] = {
    "url":          (CAT_CONTENT,   "Downstream sync target (the next vendor in the ID-sync hop)", IMPACT_MEDIUM),
    "nwid":         (CAT_TECHNICAL, "Equativ network identifier", IMPACT_LOW),
    "dcid":         (CAT_TECHNICAL, "Equativ data-center identifier", IMPACT_LOW),
    "cklb":         (CAT_TECHNICAL, "Cookie load-balancing token", IMPACT_LOW),
    "gdpr":         (CAT_CONSENT,   "IAB TCF: GDPR-applies flag", IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT,   "IAB TCF consent string", IMPACT_LOW),
}


@register
class SmartAdServerModule(TrackerModule):
    """Detect Smart AdServer / Equativ ad-server / cookie-sync traffic."""

    module_id = "smart_adserver"
    module_name = "Smart AdServer / Equativ"
    vendor = "Equativ S.A.S."
    legal_jurisdiction = "FR"
    data_residency = "EU (Paris HQ); global serving infrastructure"
    sovereignty_notes = "EU controller — no third-country transfer to the controller"
    # Ad-server / SSP cookie-sync (the ad-tech sync shape, EU-controlled):
    #   privacy 4.0 (cross-site ad profile), security 4.0 (loads
    #   CookieSync.min.js / cmp.js unpinned AND the /getuid redirect hops
    #   into demand partners the operator cannot enumerate), resilience 1.5
    #   (EU controller — matches criteo / bidswitch / adform).
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=1.5)
    impact_notes = {
        "privacy": "A cookie-sync that joins this visit to a web-wide "
            "advertising profile — cross-site by design.",
        "security": "Loads an unpinned sync/CMP script into your origin and "
            "its /getuid redirect hops the visitor into demand partners you "
            "cannot enumerate.",
        "resilience": "An EU-controlled (Equativ, France) ad dependency — "
            "replaceable, lower sovereignty exposure than a US one.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host in _HOST_EXACT or any(
            host.endswith(suffix) for suffix in _HOST_SUFFIXES
        )

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Smart AdServer parameter", IMPACT_LOW)
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
