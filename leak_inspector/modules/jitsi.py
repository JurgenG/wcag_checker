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

"""Jitsi Meet (public ``meet.jit.si``) detector.

Jitsi Meet is an open-source video-conferencing app. Sites embed the
public instance by loading its iframe API (``meet.jit.si/external_api.js``),
which then renders a meeting in an iframe. The public ``meet.jit.si``
instance is operated by **8x8, Inc.** (US); Jitsi itself is open-source
and self-hostable, so the US exposure is a property of *this* instance,
not of the software.

Privacy story: at embed time the cost is loading 8x8's JavaScript and the
presence leak. If a visitor actually joins a meeting, real-time audio /
video and any display name flow to the 8x8 instance — conditional on use.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIX = ".jit.si"
_HOST_EXACT = "jit.si"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "ver": (CAT_TECHNICAL, "Jitsi external-API script version / cache-bust tag", IMPACT_LOW),
}


@register
class JitsiModule(TrackerModule):
    """Detect Jitsi Meet public-instance (``meet.jit.si``) embeds."""

    module_id = "jitsi"
    module_name = "Jitsi Meet (meet.jit.si)"
    vendor = "8x8, Inc. (public meet.jit.si instance)"
    legal_jurisdiction = "US"
    data_residency = "8x8 (US) for the public meet.jit.si instance; Jitsi is open-source / self-hostable"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply to the public instance"
    # Embedded video-conferencing widget (public US instance): privacy 1.5
    #   (embed is a presence leak; a *joined* call sends audio/video and a
    #   display name to the 8x8 instance — conditional on use). security
    #   2.5 (loads external_api.js into the origin and iframes the meeting
    #   — unpinned executable surface). resilience 2.5 (US public instance,
    #   but Jitsi is self-hostable, so the exposure is a deployment choice).
    impact_rating = ImpactRating(privacy=1.5, security=2.5, resilience=2.5)
    impact_notes = {
        "privacy": "Embedding is a presence leak; if a visitor joins the "
            "meeting, their audio, video and display name flow to the "
            "US-operated public instance.",
        "security": "Loads the Jitsi external-API script into the page "
            "unpinned and iframes the meeting — third-party executable "
            "surface.",
        "resilience": "The public meet.jit.si instance is US-operated; "
            "Jitsi is open-source, so self-hosting removes the exposure.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Jitsi parameter", IMPACT_LOW)
            )
            params.append(ParamInfo(
                key=key, value=value, category=category, meaning=meaning,
                privacy_impact=impact, event_index=event.event_id,
            ))
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
