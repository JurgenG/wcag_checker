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

"""Belnet — para-governmental third-party detector.

Belnet is the Belgian National Research and Education Network — an
autonomous federal agency providing internet and network services to
universities, research institutions, hospitals, and various federal
public-sector agencies. Operates AS2611, which serves a significant
share of Belgian public-sector traffic (including ``matomo.bosa.be``,
seen earlier on BOSA's federal Matomo deployment).

This module matches the ``belnet.be`` corporate / service domain. The
broader sovereignty signal — that another host happens to be hosted on
Belnet's AS — is surfaced separately by the runner's ASN enrichment on
self-hosted analytics collectors (the ``(infra) hosting`` ParamInfo).
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
    "belnet.be",
)


@register
class ParaGovernmentBelnetModule(TrackerModule):
    """Detect requests to Belnet's corporate / service domain."""

    module_id = "paragov_belnet"
    module_name = "Belnet (federal research/education network)"
    vendor = "Belnet"
    legal_jurisdiction = "BE"
    data_residency = "Belnet-operated Belgian infrastructure (AS2611)"
    sovereignty_notes = "Autonomous federal agency providing network services to Belgian research / education / public sector; GDPR-bound"

    module_kind = MODULE_KIND_PARA_GOVERNMENT

    # EU para-public dependency (government-funded shared infrastructure)
    # — same posture class as the gov_* modules; see gov_brussels for the
    # rationale. privacy 1.0 / security 1.0 / resilience 0.5.
    impact_rating = ImpactRating(privacy=1.0, security=1.0, resilience=0.5)

    def matches(self, event: RequestEvent) -> bool:
        return host_matches_suffix_set(event.host, suffix_matches=_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        return build_public_sector_hit(self, event)
