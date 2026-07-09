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

"""LiveRamp identity-resolution detector.

LiveRamp operates an identity-resolution platform whose central
artefact is RampID (formerly IdentityLink) — a deterministic
cross-publisher, cross-device person-level identifier built from
hashed PII and onboarded offline data. The pixel calls observed on
publisher pages sync each partner's first-party user ID into RampID.

Recognized hosts: ``*.rlcdn.com`` (the LiveRamp CDN). The path
typically encodes the LiveRamp-side partner ID (``/<partner-id>.gif``
or ``/p?...``); the request body / query string carries the
partner-supplied user ID to be linked to the visitor's RampID.

Notable endpoints:

* ``/<numeric-partner-id>.gif`` — partner-pixel cookie-sync.
* ``/idsync.json`` — JSON identity-sync endpoint.
* ``/p`` — partner pixel (alt form).
"""

from __future__ import annotations

import re

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


_HOST_SUFFIX = ".rlcdn.com"
_HOST_EXACT = "rlcdn.com"

_PARTNER_PATH_RE = re.compile(r"^/(\d+)\.gif$")


_PARAMS: dict[str, tuple[str, str, str]] = {
    "partner_uid": (CAT_IDENTIFIER, "Partner-supplied user ID being linked to RampID", IMPACT_HIGH),
    "uid":         (CAT_IDENTIFIER, "Partner-supplied user ID (alt form)",              IMPACT_HIGH),
    "pid":         (CAT_TECHNICAL,  "Partner / publisher ID",                           IMPACT_LOW),
    "r":           (CAT_TECHNICAL, "Redirect target after sync completes",              IMPACT_LOW),
    "redir":       (CAT_TECHNICAL, "Redirect target (alt form)",                        IMPACT_LOW),
    "gdpr":         (CAT_CONSENT, "GDPR-applies flag (0/1)",                            IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "IAB TCF consent string",                             IMPACT_LOW),
    "us_privacy":   (CAT_CONSENT, "IAB CCPA US-privacy string",                         IMPACT_LOW),
}


@register
class LiveRampModule(TrackerModule):
    """Detect LiveRamp identity-resolution cookie-sync traffic."""

    module_id = "liveramp"
    module_name = "LiveRamp"
    vendor = "LiveRamp Holdings, Inc."
    legal_jurisdiction = "US"
    data_residency = "US (San Francisco, CA HQ); global serving infrastructure"
    sovereignty_notes = (
        "US CLOUD Act / FISA 702 apply; RampID is a cross-publisher person-level "
        "identifier built from hashed PII"
    )
    # privacy 5.0: RampID is a deterministic cross-publisher, cross-device
    #   *person-level* identifier built from hashed PII + offline onboarded
    #   data — identity resolution by design, "no longer pseudonymous
    #   anywhere in the chain" (rubric privacy 5.0). The one module in 3c
    #   that earns the top privacy rating, distinct from the 4.0 SSPs.
    # security 3.0: ID-sync pixel/library distributing a person-level ID,
    #   broad but not an OpenRTB auction hub. resilience 2.5: US supporting
    #   identity layer (rubric 2.5).
    impact_notes = {
        "privacy": "RampID is a deterministic, cross-publisher, "
            "cross-device person-level identifier built from hashed PII — "
            "the visitor is no longer pseudonymous anywhere in the chain.",
        "security": "Distributes a person-level identifier broadly via "
            "ID-sync pixels.",
        "resilience": "A US identity-resolution layer the targeting "
            "depends on.",
    }
    impact_rating = ImpactRating(privacy=5.0, security=3.0, resilience=2.5)

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []

        from urllib.parse import urlparse
        path = urlparse(event.url).path
        partner_match = _PARTNER_PATH_RE.match(path)
        if partner_match:
            params.append(
                ParamInfo(
                    key="(path) partner_id",
                    value=partner_match.group(1),
                    category=CAT_TECHNICAL,
                    meaning="LiveRamp partner ID embedded in the pixel URL path",
                    privacy_impact=IMPACT_LOW,
                    event_index=event.event_id,
                )
            )

        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized LiveRamp parameter", IMPACT_LOW)
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
