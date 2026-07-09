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

"""Federal Belgian government — governmental third-party detector.

Claims requests to the four official multilingual Belgian-government
domains (``belgium.be`` / ``belgique.be`` / ``belgien.be`` / ``belgie.be``)
and the ``.fgov.be`` federal-government suffix.

``.bosa.be`` (FOD BOSA, the federal IT agency) is explicitly excluded:
its visible third-party endpoints are Matomo deployments, which are more
informatively classified by the Matomo module.
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


# The four official multilingual variants + the federal-government suffix.
_SUFFIXES: tuple[str, ...] = (
    "belgium.be",
    "belgique.be",
    "belgien.be",
    "belgie.be",
    "fgov.be",
)

# Carved out so that more-specific trackers on these hosts win.
_EXCLUDED: tuple[str, ...] = (
    "bosa.be",
)


@register
class GovernmentFederalBelgiumModule(TrackerModule):
    """Detect requests to federal Belgian government domains."""

    module_id = "gov_federal_belgium"
    module_name = "Federal Belgian government"
    vendor = "Federal Government of Belgium"
    legal_jurisdiction = "BE"
    data_residency = "Belgian federal infrastructure (typically operated by FOD BOSA)"
    sovereignty_notes = "GDPR-bound public-sector entity; subject to Belgian federal data-protection oversight"

    module_kind = MODULE_KIND_GOVERNMENT
    government_level = "federal_be"

    # EU public-sector dependency — see gov_brussels for the shared
    # rationale. privacy 1.0 / security 1.0 / resilience 0.5.
    impact_rating = ImpactRating(privacy=1.0, security=1.0, resilience=0.5)

    def matches(self, event: RequestEvent) -> bool:
        return host_matches_suffix_set(
            event.host,
            suffix_matches=_SUFFIXES,
            excluded_suffixes=_EXCLUDED,
        )

    def parse(self, event: RequestEvent) -> Hit:
        return build_public_sector_hit(self, event)
