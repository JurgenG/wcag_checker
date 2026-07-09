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

"""Brussels-Capital Region government — governmental third-party detector.

The ``.brussels`` TLD is open-registration and used by both the
Brussels-Capital regional government AND by the 19 Brussels municipalities
(``evere.brussels``, ``etterbeek.brussels`` …). To avoid mis-classifying
municipal sites as "regional government", this module matches only an
explicit allow-list of regional-government second-level domains rather
than a blanket ``.brussels`` suffix.

Sources for the allow-list: the official Brussels-Capital portal
(``be.brussels``) and well-known regional institutions (Parliament,
finance / tax administration, Innoviris research agency, regional
public-sector employer brands). Add new entries as further regional
domains are observed in captures — *do not* expand to a blanket TLD
match.
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


# Explicit allow-list of Brussels-Capital regional-government domains.
_SUFFIXES: tuple[str, ...] = (
    "be.brussels",            # official Brussels-Capital regional portal
    "parliament.brussels",    # Brussels Parliament
    "tax.brussels",           # Brussels-Capital regional tax administration
    "innoviris.brussels",     # Brussels regional research-funding agency
)


@register
class GovernmentBrusselsModule(TrackerModule):
    """Detect requests to Brussels-Capital regional government domains."""

    module_id = "gov_brussels"
    module_name = "Brussels-Capital government"
    vendor = "Brussels-Capital Region / Région de Bruxelles-Capitale / Brussels Hoofdstedelijk Gewest"
    legal_jurisdiction = "BE"
    data_residency = "Brussels-Capital regional infrastructure"
    sovereignty_notes = "GDPR-bound; the .brussels TLD is open-registration so this module matches an explicit allow-list of regional-government domains only"

    module_kind = MODULE_KIND_GOVERNMENT
    government_level = "regional_brussels_capital"

    # EU public-sector dependency — the posture this project encourages.
    # privacy 1.0: presence-of-visit (and, on SSO flows, citizen identity)
    #   disclosed to a separate but EU/GDPR-bound public controller —
    #   never traded onward (rubric privacy 1.0). security 1.0: a
    #   content/widget from an accountable EU public host (rubric 1.0).
    # resilience 0.5: an external dependency, but the most sovereign kind
    #   — EU public sector, democratically accountable (rubric 0.5).
    impact_rating = ImpactRating(privacy=1.0, security=1.0, resilience=0.5)

    def matches(self, event: RequestEvent) -> bool:
        return host_matches_suffix_set(event.host, suffix_matches=_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        return build_public_sector_hit(self, event)
