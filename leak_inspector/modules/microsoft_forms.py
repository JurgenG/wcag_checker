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

"""Microsoft Forms detector.

Microsoft Forms is the Microsoft 365 survey / form / quiz service. Sites
embed a form's response page (``/Pages/ResponsePage.aspx?id=...&embed=true``)
and the widget loads its bundles from ``/cdn/scripts/...`` and reads the
form definition from ``/formapi/api/<tenant>/users/<user>/...``.

Recognised hosts:

* ``forms.cloud.microsoft`` — the current Forms host (observed).
* ``forms.office.com`` — the documented legacy Forms host.

Privacy story: a form / survey collects whatever the operator asks for,
which can include name / email / free-text — landing in the operator's
Microsoft 365 tenant (US controller). The ``id`` parameter is the
form's own identifier (operator config, identical for every visitor),
not a visitor pseudonym; tenant / user GUIDs live in the API path.
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


_HOSTS: frozenset[str] = frozenset({
    "forms.cloud.microsoft",
    "forms.office.com",
})


_PARAMS: dict[str, tuple[str, str, str]] = {
    "id":      (CAT_TECHNICAL, "Form identifier (operator config — same for every visitor)", IMPACT_LOW),
    "embed":   (CAT_TECHNICAL, "Embedded-rendering flag", IMPACT_LOW),
    "$expand": (CAT_TECHNICAL, "OData expansion of the form definition query", IMPACT_LOW),
    "$top":    (CAT_TECHNICAL, "OData result-count limit", IMPACT_LOW),
}


@register
class MicrosoftFormsModule(TrackerModule):
    """Detect Microsoft Forms (survey / form / quiz) embeds."""

    module_id = "microsoft_forms"
    module_name = "Microsoft Forms"
    vendor = "Microsoft Corporation"
    legal_jurisdiction = "US"
    data_residency = "Microsoft 365 (operator's tenant); US controller"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Embedded form / survey functional service: privacy 2.0 (collects
    #   whatever the operator's form asks for — potentially name/email/
    #   free-text — into the operator's M365 tenant; operator-intended,
    #   not profiling). security 2.5 (serves its own JavaScript bundles
    #   into the page from ``/cdn/scripts`` — unpinned executable surface,
    #   cf. microsoft_onecdn). resilience 3.0 (US Microsoft 365 dependency
    #   for a site function).
    impact_rating = ImpactRating(privacy=2.0, security=2.5, resilience=3.0)
    impact_notes = {
        "privacy": "A form / survey collects whatever the operator asks "
            "for — potentially name, email and free text — into the "
            "operator's Microsoft 365 tenant (US controller).",
        "security": "Loads its own JavaScript bundles into the page "
            "unpinned — third-party executable surface.",
        "resilience": "A US Microsoft 365 service the site depends on for "
            "its embedded form.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return event.host.lower() in _HOSTS

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Microsoft Forms parameter", IMPACT_LOW)
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
