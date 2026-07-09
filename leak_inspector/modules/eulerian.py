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

"""Eulerian detector.

Eulerian Technologies SAS (Paris) is a French marketing-attribution
platform repeatedly named in the CNAME-cloaking literature ("The
CNAME of the Game", NextDNS blocklist) as one of the pioneers of the
technique: customers alias a first-party subdomain to
``<customer>.eulerian.net`` so attribution traffic evades tracker
blocklists and third-party-cookie restrictions.
"""

from __future__ import annotations

from ..impact import ImpactRating
from ._cname_cloak_base import CnameCloakVendorModule
from .base import register


@register
class EulerianModule(CnameCloakVendorModule):
    """Detect Eulerian attribution requests (usually CNAME-cloaked)."""

    module_id = "eulerian"
    module_name = "Eulerian"
    vendor = "Eulerian Technologies SAS"
    legal_jurisdiction = "FR"
    data_residency = "Eulerian-operated infrastructure (France/EU)"
    sovereignty_notes = (
        "EU controller (French SAS, CNIL supervision). Eulerian is one "
        "of the canonical CNAME-cloaking vendors: deployment via a "
        "first-party-looking alias is its documented default, so a hit "
        "almost always indicates deliberate tracker-blocklist evasion "
        "even though the jurisdiction itself is EU."
    )
    canonical_domains = ("eulerian.net",)
    # CNAME-cloaked tracker → 4.5 / 2.5 / 1.5 (EU vendor, France). See
    # commanders_act for the shared shape.
    impact_rating = ImpactRating(privacy=4.5, security=2.5, resilience=1.5)
    impact_notes = {
        "privacy": "A CNAME-cloaked tracker — disguised as first-party so "
            "it evades blockers and consent expectations.",
        "security": "First-party-served vendor JavaScript, unpinned.",
        "resilience": "An EU vendor (France), GDPR-native.",
    }
