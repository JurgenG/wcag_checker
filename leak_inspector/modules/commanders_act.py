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

"""Commanders Act detector.

Commanders Act SAS (Paris; historically TagCommander) operates a
tag-management + customer-data platform. Detection domains:

* ``tagcommander.com`` — tag-container serving (``cdn.tagcommander.com``)
  and the documented CNAME-cloaking tail (NextDNS blocklist).
* ``commander1.com`` — event/data collection
  (``engage.commander1.com``, ``collect.commander1.com``).
"""

from __future__ import annotations

from ..impact import ImpactRating
from ._cname_cloak_base import CnameCloakVendorModule
from .base import register


@register
class CommandersActModule(CnameCloakVendorModule):
    """Detect Commanders Act (TagCommander) requests."""

    module_id = "commanders_act"
    module_name = "Commanders Act"
    vendor = "Commanders Act SAS"
    legal_jurisdiction = "FR"
    data_residency = "Commanders Act-operated infrastructure (France/EU)"
    sovereignty_notes = (
        "EU controller (French SAS, CNIL supervision). tagcommander.com "
        "is a documented CNAME-cloaking tail (NextDNS blocklist): "
        "customers alias a first-party subdomain to it so the tag "
        "container and collection traffic evade tracker blocklists. As "
        "a tag manager it also loads arbitrary downstream vendors, so a "
        "hit understates the real third-party graph."
    )
    canonical_domains = ("tagcommander.com", "commander1.com")
    # CNAME-cloaked tracker → privacy 4.5 (evasion override) / security
    #   2.5 (unpinned vendor JS) / resilience 1.5 (EU vendor, France —
    #   GDPR-native with switching costs; rubric 1.5).
    impact_rating = ImpactRating(privacy=4.5, security=2.5, resilience=1.5)
    impact_notes = {
        "privacy": "A CNAME-cloaked tracker — disguised as first-party so "
            "it evades blockers and consent expectations.",
        "security": "First-party-served vendor JavaScript, unpinned.",
        "resilience": "An EU vendor (France), GDPR-native.",
    }
