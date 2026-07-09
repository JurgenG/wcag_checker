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

"""ChatHive AI-chat-agent detector.

ChatHive (a Bothive product, Ghent, Belgium) provides AI chat agents
for email and chat, marketed to accountants, brokers, governments and
SMEs. The embeddable widget loads its SDK from ``sdk.chathive.app``; the
chat content (and, with human-handoff enabled, the full conversation
history) is processed by ChatHive.

Recognized hosts: any subdomain of ``chathive.app``. Chat content
travels in request bodies v1.0 capture does not record.
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


_HOST_SUFFIX = ".chathive.app"
_HOST_EXACT = "chathive.app"


@register
class ChatHiveModule(TrackerModule):
    """Detect ChatHive AI-chat-agent widget traffic."""

    module_id = "chathive"
    module_name = "ChatHive"
    vendor = "ChatHive (Bothive)"
    legal_jurisdiction = "BE"
    data_residency = "EU (Belgium) — Bothive / ChatHive, Ghent"
    sovereignty_notes = "EU-controlled (Belgium) — GDPR-native, no Schrems II concern"
    # AI chat-agent widget at a contained EU/Belgian vendor: privacy 2.5
    #   (the visitor's chat content is processed by ChatHive — and the
    #   conversation history can be emailed for human follow-up — contained,
    #   not a cross-site tracker), security 2.5 (an unpinned widget SDK runs
    #   in your origin), resilience 1.0 (EU vendor, GDPR-native).
    impact_rating = ImpactRating(privacy=2.5, security=2.5, resilience=1.0)
    impact_notes = {
        "privacy": "The visitor's chat content is processed by ChatHive "
            "(conversation history can be emailed for human follow-up) — a "
            "contained EU vendor, not a cross-site tracker.",
        "security": "Loads an unpinned chat-agent SDK into your origin.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            params.append(
                ParamInfo(
                    key=key, value=value, category=CAT_OTHER,
                    meaning="ChatHive widget parameter — unclassified",
                    privacy_impact=IMPACT_LOW, event_index=event.event_id,
                )
            )
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
