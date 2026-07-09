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

"""Cultuurconnect — para-governmental third-party detector.

Cultuurconnect vzw is a Flemish non-profit funded by the Flemish
government to operate shared digital infrastructure for Flemish public
libraries and cultural institutions (e.g. the bibnet library platform,
Mijn Bibliotheek, digitale leeszaal).
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
    "cultuurconnect.be",
)


@register
class ParaGovernmentCultuurconnectModule(TrackerModule):
    """Detect requests to Cultuurconnect infrastructure."""

    module_id = "paragov_cultuurconnect"
    module_name = "Cultuurconnect (Flemish library / cultural infrastructure)"
    vendor = "Cultuurconnect vzw"
    legal_jurisdiction = "BE"
    data_residency = "Cultuurconnect-operated infrastructure in Flanders"
    sovereignty_notes = "Flemish-government-funded non-profit serving public libraries and cultural institutions; GDPR-bound"

    module_kind = MODULE_KIND_PARA_GOVERNMENT

    # EU para-public dependency — see gov_brussels for the shared
    # rationale. privacy 1.0 / security 1.0 / resilience 0.5.
    impact_rating = ImpactRating(privacy=1.0, security=1.0, resilience=0.5)

    def matches(self, event: RequestEvent) -> bool:
        return host_matches_suffix_set(event.host, suffix_matches=_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        return build_public_sector_hit(self, event)
