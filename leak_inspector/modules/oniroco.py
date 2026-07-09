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

"""Oniroco conversational-AI chatbot detector.

Oniroco (oniroco.eu — an EU / Belgian vendor) provides an AI chatbot
that answers citizen questions on municipal websites (plus smart forms
and an AI mail assistant). The embeddable widget loads from
``widget.oniroco.app`` and initialises against ``api.oniroco.app``
(``/sdk/v1/widget/init?key=<per-site key>``, ``/sdk/trpc``); the chat
itself sends the visitor's questions to Oniroco to generate answers.

Recognized hosts: any subdomain of ``oniroco.app``. The per-site
``key`` rides in the query string; chat content travels in request
bodies v1.0 capture does not record.
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


_HOST_SUFFIX = ".oniroco.app"
_HOST_EXACT = "oniroco.app"


@register
class OnirocoModule(TrackerModule):
    """Detect Oniroco conversational-AI chatbot widget traffic."""

    module_id = "oniroco"
    module_name = "Oniroco"
    vendor = "Oniroco"
    legal_jurisdiction = "EU"
    data_residency = "EU (Belgian / EU vendor; oniroco.eu)"
    sovereignty_notes = (
        "EU vendor (Belgian municipal / accounting market) — GDPR-native, "
        "no Schrems II transfer concern"
    )
    # Conversational-AI chat widget at a contained EU vendor: privacy 2.5
    #   (the visitor's chat questions are sent to Oniroco to generate
    #   answers — contained, not a cross-site tracker), security 2.5 (an
    #   unpinned widget SDK runs in your origin), resilience 1.0 (EU vendor,
    #   GDPR-native).
    impact_rating = ImpactRating(privacy=2.5, security=2.5, resilience=1.0)
    impact_notes = {
        "privacy": "The visitor's chat questions are sent to Oniroco to "
            "generate answers — a contained EU vendor, not a cross-site "
            "tracker.",
        "security": "Loads an unpinned chatbot SDK into your origin.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            if key == "key":
                category, meaning = CAT_TECHNICAL, "Per-site Oniroco widget key (tenant id, not a visitor id)"
            else:
                category, meaning = CAT_OTHER, "Oniroco widget parameter — unclassified"
            params.append(
                ParamInfo(
                    key=key, value=value, category=category, meaning=meaning,
                    privacy_impact=IMPACT_LOW, event_index=event.event_id,
                )
            )
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
