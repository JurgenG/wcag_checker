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

"""AddToAny share-buttons detector.

AddToAny (AddToAny Holdings LLC, San Francisco, US) is a universal
social-share widget. Its JavaScript loads from ``static.addtoany.com``
(``/menu/page.js``, ``/menu/modules/core.*.js``, ``/menu/sm.*.html``)
and renders share buttons that connect onward to the chosen social
networks when clicked.

Recognized hosts: any subdomain of ``addtoany.com``.
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


_HOST_SUFFIX = ".addtoany.com"
_HOST_EXACT = "addtoany.com"


@register
class AddToAnyModule(TrackerModule):
    """Detect AddToAny share-buttons widget traffic."""

    module_id = "addtoany"
    module_name = "AddToAny"
    vendor = "AddToAny Holdings LLC"
    legal_jurisdiction = "US"
    data_residency = "US (San Francisco, CA); global serving infrastructure"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Social-share widget (US): privacy 2.0 (the script sees the page
    #   context + share intent and reports to a US vendor — contained, not a
    #   persistent cross-site ad profile), security 2.5 (an unpinned widget
    #   script runs in your origin), resilience 2.5 (US vendor, replaceable
    #   supporting feature).
    impact_rating = ImpactRating(privacy=2.0, security=2.5, resilience=2.5)
    impact_notes = {
        "privacy": "The share widget sees the page context and share "
            "intent and reports to a US vendor; clicking a button connects "
            "onward to the chosen social network.",
        "security": "Loads an unpinned share-widget script into your "
            "origin.",
        "resilience": "A US vendor for a replaceable supporting feature.",
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
                    meaning="AddToAny widget parameter — unclassified",
                    privacy_impact=IMPACT_LOW, event_index=event.event_id,
                )
            )
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
