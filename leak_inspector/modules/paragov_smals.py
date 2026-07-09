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

"""Smals — para-governmental third-party detector.

Smals vzw is a Belgian non-profit jointly created by federal social-
security and health institutions to provide them with shared IT services
(applications, hosting, identity infrastructure). Not formally part of
government — its members are the federal agencies it serves — but
operationally a public-sector IT provider.
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
    "smals.be",
)


@register
class ParaGovernmentSmalsModule(TrackerModule):
    """Detect requests to Smals infrastructure."""

    module_id = "paragov_smals"
    module_name = "Smals (federal social-security IT)"
    vendor = "Smals vzw"
    legal_jurisdiction = "BE"
    data_residency = "Smals-operated Belgian infrastructure"
    sovereignty_notes = "Belgian non-profit jointly owned by federal social-security / health institutions; GDPR-bound"

    module_kind = MODULE_KIND_PARA_GOVERNMENT

    # EU para-public dependency — see gov_brussels for the shared
    # rationale. privacy 1.0 / security 1.0 / resilience 0.5.
    impact_rating = ImpactRating(privacy=1.0, security=1.0, resilience=0.5)

    def matches(self, event: RequestEvent) -> bool:
        return host_matches_suffix_set(event.host, suffix_matches=_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        return build_public_sector_hit(self, event)
