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

"""SurveyMonkey website-collector widget detector.

SurveyMonkey (SVMK / Momentive, San Mateo, CA, US) is a survey
platform. Its embedded "website collector" widget loads from
``widget.surveymonkey.com`` (``/collect/website/js/<token>.js``) and
pops a survey on the host site; the visitor's responses are submitted
to SurveyMonkey.

Recognized hosts: any subdomain of ``surveymonkey.com``. Survey
responses travel in request bodies v1.0 capture does not record.
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


_HOST_SUFFIX = ".surveymonkey.com"
_HOST_EXACT = "surveymonkey.com"


@register
class SurveyMonkeyModule(TrackerModule):
    """Detect SurveyMonkey website-collector widget traffic."""

    module_id = "surveymonkey"
    module_name = "SurveyMonkey"
    vendor = "SurveyMonkey (Momentive)"
    legal_jurisdiction = "US"
    data_residency = "US (San Mateo, CA HQ); global serving infrastructure"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Embedded survey widget (US): privacy 2.5 (the visitor's survey
    #   responses — opinions, free text, sometimes contact details — are
    #   submitted to a US controller), security 2.5 (an unpinned widget
    #   script runs in your origin), resilience 2.5 (US vendor, replaceable).
    impact_rating = ImpactRating(privacy=2.5, security=2.5, resilience=2.5)
    impact_notes = {
        "privacy": "The visitor's survey responses (opinions, free text, "
            "sometimes contact details) are submitted to a US controller.",
        "security": "Loads an unpinned survey-widget script into your "
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
                    meaning="SurveyMonkey widget parameter — unclassified",
                    privacy_impact=IMPACT_LOW, event_index=event.event_id,
                )
            )
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
