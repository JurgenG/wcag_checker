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

"""Flemish government (Vlaanderen) — governmental third-party detector.

Claims requests to ``vlaanderen.be`` and all subdomains — the unified
domain used by the Flemish regional government for citizen widgets
(``prod.widgets.burgerprofiel.vlaanderen.be``, ``widgets.vlaanderen.be``),
authentication (``authenticatie.vlaanderen.be``), and contact-info APIs
(``contactapi.vlaanderen.be``). These are by far the most frequently
embedded governmental third parties in Flemish municipal sites.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from ._public_sector_base import build_public_sector_hit, host_matches_suffix_set
from .base import (
    Hit,
    MODULE_KIND_GOVERNMENT,
    TrackerModule,
    register,
)


_SUFFIXES: tuple[str, ...] = (
    "vlaanderen.be",
)


@register
class GovernmentFlandersModule(TrackerModule):
    """Detect requests to Flemish regional government domains."""

    module_id = "gov_flanders"
    module_name = "Flemish government (Vlaanderen)"
    vendor = "Government of Flanders / Vlaamse overheid"
    legal_jurisdiction = "BE"
    data_residency = "Flemish regional infrastructure"
    sovereignty_notes = "GDPR-bound; widgets typically include a Mijn Burgerprofiel SSO flow"

    module_kind = MODULE_KIND_GOVERNMENT
    government_level = "regional_vlaanderen"

    # EU public-sector dependency — see gov_brussels for the shared
    # rationale (Mijn Burgerprofiel SSO is the identity case). privacy
    # 1.0 / security 1.0 / resilience 0.5.
    impact_rating = ImpactRating(privacy=1.0, security=1.0, resilience=0.5)

    def matches(self, event: RequestEvent) -> bool:
        return host_matches_suffix_set(event.host, suffix_matches=_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        return build_public_sector_hit(self, event)
