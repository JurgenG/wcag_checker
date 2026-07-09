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

"""ReadSpeaker text-to-speech (web-reader) detector.

ReadSpeaker AB (Uppsala, Sweden; ops in the Netherlands — EU) provides
the "webReader" text-to-speech widget very widely embedded on EU
public-sector / municipal sites for accessibility. The widget loads
from ``*.readspeaker.com`` (``cdn1.``, ``cdn-eu.``, ``f1-eu.``) at
``/script/<customer-id>/webReader/webReader.js`` and, to synthesise
speech, sends the **text of the page** (or the selected passage) to
ReadSpeaker's servers.

Recognized hosts: any subdomain of ``readspeaker.com``. The per-site
``customer-id`` rides in the path; query parameters seen are
``pids`` / ``v`` plumbing, surfaced unclassified.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_OTHER,
    Hit,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIX = ".readspeaker.com"
_HOST_EXACT = "readspeaker.com"


@register
class ReadSpeakerModule(TrackerModule):
    """Detect ReadSpeaker text-to-speech web-reader traffic."""

    module_id = "readspeaker"
    module_name = "ReadSpeaker"
    vendor = "ReadSpeaker AB"
    legal_jurisdiction = "EU"
    data_residency = "EU (Sweden / Netherlands); ReadSpeaker AB is a HOYA Corporation subsidiary"
    sovereignty_notes = (
        "EU controller (Sweden/Netherlands) — GDPR-native, no Schrems II "
        "transfer concern; parent company HOYA Corporation is Japanese"
    )
    # Accessibility text-to-speech widget at a contained EU vendor:
    #   privacy 1.5 (the widget sends page text + a presence signal to
    #   synthesise speech — contained, not a cross-site ad profile),
    #   security 2.5 (unpinned third-party JS in the origin — the
    #   accessibility-widget class burned by the 2018 Browsealoud
    #   supply-chain attack), resilience 1.0 (EU vendor, GDPR-native).
    impact_rating = ImpactRating(privacy=1.5, security=2.5, resilience=1.0)
    impact_notes = {
        "privacy": "To read the page aloud, the widget sends the page text "
            "(or selection) to ReadSpeaker — a contained EU vendor, not a "
            "cross-site tracker.",
        "security": "Runs unpinned third-party JavaScript in your origin — "
            "the accessibility-widget class burned by the 2018 Browsealoud "
            "supply-chain compromise.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            params.append(
                ParamInfo(
                    key=key,
                    value=value,
                    category=CAT_OTHER,
                    meaning="ReadSpeaker web-reader parameter — unclassified",
                    privacy_impact=IMPACT_LOW,
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
