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

"""IMIO — para-governmental third-party detector.

IMIO (Intercommunale de Mutualisation en matière Informatique et
Organisationnelle) is a Walloon intercommunal association that provides
shared IT services to Walloon municipalities and CPAS social-service
agencies. It is not formally part of government — it is a publicly-owned
non-profit — but it operates on behalf of the public sector and runs
infrastructure embedded across Walloon municipal websites (CMS, content
delivery, analytics).

Registration order: this module is imported AFTER all tracker modules
so that specific trackers running on imio.be subdomains (e.g. a Plausible
instance at ``plausible.imio.be``) win first-match-wins and stay
classified as the tracker rather than as IMIO infrastructure.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from ._public_sector_base import build_public_sector_hit, host_matches_suffix_set
from .base import (
    Hit,
    MODULE_KIND_PARA_GOVERNMENT,
    TrackerModule,
    register,
)


_SUFFIXES: tuple[str, ...] = (
    "imio.be",
)


@register
class ParaGovernmentImioModule(TrackerModule):
    """Detect requests to IMIO infrastructure."""

    module_id = "paragov_imio"
    module_name = "IMIO (Walloon intercommunal IT)"
    vendor = "IMIO (Intercommunale de Mutualisation en matière Informatique et Organisationnelle)"
    legal_jurisdiction = "BE"
    data_residency = "Walloon intercommunal infrastructure"
    sovereignty_notes = "Publicly-owned non-profit serving Walloon municipalities and CPAS; GDPR-bound"

    module_kind = MODULE_KIND_PARA_GOVERNMENT

    # EU para-public dependency — see gov_brussels for the shared
    # rationale. privacy 1.0 / security 1.0 / resilience 0.5.
    impact_rating = ImpactRating(privacy=1.0, security=1.0, resilience=0.5)

    def matches(self, event: RequestEvent) -> bool:
        return host_matches_suffix_set(event.host, suffix_matches=_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        return build_public_sector_hit(self, event)
