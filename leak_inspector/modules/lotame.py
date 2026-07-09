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

"""Lotame DMP detector.

Lotame operates a data-management platform (DMP). Its cookie-sync
pixel encodes its parameters in the URL **path** rather than the
query string — values are written as ``/<key>=<value>/`` segments
under ``/map/...``, similar in spirit to Adobe demdex's ``/ibs:`` form.

Recognized hosts: ``*.crwdcntrl.net`` (Lotame's serving CDN). Notable
endpoint:

* ``/map/c=<clientID>/tp=<third-party-source>/gdpr=<flag>/gdpr_consent=<str>/tpid=<third-party-user-ID>``
  — the cookie-match handler that syncs a third-party's user ID
  (``tpid``) against Lotame's audience graph.

We parse the slash-separated path segments into named ``ParamInfo``
rows so the report surfaces who initiated the sync, who is being
synced, and how.
"""

from __future__ import annotations

from urllib.parse import urlparse

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


_HOST_SUFFIX = ".crwdcntrl.net"
_HOST_EXACT = "crwdcntrl.net"


_PATH_PARAMS: dict[str, tuple[str, str, str]] = {
    "c":            (CAT_TECHNICAL,  "Lotame client / customer ID",                          IMPACT_LOW),
    "tp":           (CAT_TECHNICAL,  "Third-party data source initiating the sync (e.g. ``ADBE`` = Adobe AAM)", IMPACT_LOW),
    "tpid":         (CAT_IDENTIFIER, "Third-party user ID being synced into Lotame's graph", IMPACT_HIGH),
    "gdpr":         (CAT_CONSENT,    "GDPR-applies flag (0/1)",                              IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT,    "IAB TCF consent string",                               IMPACT_LOW),
    "us_privacy":   (CAT_CONSENT,    "IAB CCPA US-privacy string",                           IMPACT_LOW),
}


def _parse_map_path(path: str) -> list[tuple[str, str]]:
    """Extract ``key=value`` segments from a ``/map/...`` Lotame path."""
    if not path.startswith("/map/"):
        return []
    out: list[tuple[str, str]] = []
    for segment in path[len("/map/"):].split("/"):
        if "=" not in segment:
            continue
        key, _, value = segment.partition("=")
        out.append((key.strip(), value.strip()))
    return out


@register
class LotameModule(TrackerModule):
    """Detect Lotame DMP cookie-sync traffic."""

    module_id = "lotame"
    module_name = "Lotame"
    vendor = "Lotame Solutions, Inc."
    legal_jurisdiction = "US"
    data_residency = "US (Columbia, MD HQ); global serving infrastructure"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # DMP: privacy 4.0 (cross-site audience profile), security 4.0
    # (cookie-sync hub redistributing the pseudonym to partners),
    # resilience 2.5 (US supporting). Shape as the SSPs (see appnexus).
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=2.5)
    impact_notes = {
        "privacy": "A data-management platform that joins this visit to a "
            "web-wide audience profile — cross-site by design.",
        "security": "A cookie-sync hub redirects the visitor's pseudonym "
            "into partners you cannot enumerate.",
        "resilience": "A US data dependency, replaceable but "
            "foreign-controlled.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []

        path = urlparse(event.url).path
        for key, value in _parse_map_path(path):
            category, meaning, impact = _PATH_PARAMS.get(
                key,
                (CAT_OTHER, "Unrecognized Lotame path parameter", IMPACT_LOW),
            )
            params.append(
                ParamInfo(
                    key=f"(path) {key}",
                    value=value,
                    category=category,
                    meaning=meaning,
                    privacy_impact=impact,
                    event_index=event.event_id,
                )
            )

        for key, value in event.all_params.items():
            category, meaning, impact = _PATH_PARAMS.get(
                key,
                (CAT_OTHER, "Unrecognized Lotame parameter", IMPACT_LOW),
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
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
