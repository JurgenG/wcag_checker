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

"""Letsgocity (civic / municipal "… en poche" platform) detector.

Letsgocity is a Belgian Smart-City vendor (Wallonia; now part of the NRB
group via Afelio / Inforius) that builds citizen portals and apps for
public authorities — the "Wallonie en poche" / "Ma commune en poche"
family used by 60+ Walloon municipalities. Its content backbone is
embedded in those municipal sites:

* ``files.letsgocity.be`` — image / media host (UUID objects,
  ``/resize/<WxH>/`` and ``/crop-resize/`` variants).
* ``api.letsgocity.be`` — public API incl. ``/file-view-service/`` (document
  conversion / viewing).
* ``mapi.letsgocity.be`` / ``internal-api.letsgocity.be`` — the mobile /
  internal APIs powering the portal.

It is a **Belgian (EU)** vendor, so — like Icordis — it draws no
resilience / sovereignty penalty; it is the kind of decentralised EU
infrastructure this project encourages. It is still a third-party
dependency the visitor's browser contacts (disclosing IP / ``User-Agent``
/ ``Referer``), so it is classified rather than left "unclassified".
Requests carry no tracking parameters; any URL params are surfaced as
``CAT_OTHER`` so they stay inspectable.
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


_HOST_SUFFIX = ".letsgocity.be"
_HOST_EXACT = "letsgocity.be"


@register
class LetsgocityModule(TrackerModule):
    """Detect Letsgocity municipal-portal content / API requests."""

    module_id = "letsgocity"
    module_name = "Letsgocity"
    vendor = "Letsgocity (NRB group)"
    legal_jurisdiction = "BE"
    data_residency = "EU (Belgium); Letsgocity is part of the NRB group (Wallonia)"
    sovereignty_notes = (
        "Belgian (EU) civic-tech vendor serving public authorities — "
        "GDPR-native, no Schrems II concern. Part-owned via the NRB group, "
        "which has significant Belgian public-sector ownership; the EU "
        "hosting is a positive sovereignty signal."
    )
    # Belgian/EU municipal content + API platform (like Icordis): privacy
    #   1.0 (a third-party data flow / presence leak, but to an EU vendor
    #   serving municipal content — no tracking payload), security 1.0
    #   (third-party content / API surface embedded in the page), resilience
    #   0.5 (EU/Belgian — the encouraged sovereign posture). No domain
    #   exceeds 1.0, so no impact_notes are required.
    impact_rating = ImpactRating(privacy=1.0, security=1.0, resilience=0.5)

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
                    meaning="Letsgocity platform parameter — unclassified",
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
