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

"""Webtrekk / Mapp Intelligence detector.

Webtrekk GmbH (Berlin) was acquired in 2019 by Mapp Digital US, LLC
(San Diego); the analytics product continues as Mapp Intelligence.
The NextDNS cname-cloaking blocklist documents two canonical tails
customers alias first-party subdomains to: ``webtrekk.net`` (classic
``track.webtrekk.net`` collection) and ``wt-eu02.net``.
"""

from __future__ import annotations

from ..impact import ImpactRating
from ._cname_cloak_base import CnameCloakVendorModule
from .base import register


@register
class WebtrekkMappModule(CnameCloakVendorModule):
    """Detect Webtrekk / Mapp Intelligence analytics requests."""

    module_id = "webtrekk_mapp"
    module_name = "Webtrekk (Mapp Intelligence)"
    vendor = "Mapp Digital US, LLC"
    legal_jurisdiction = "US"
    data_residency = (
        "Webtrekk collection infrastructure (historically Berlin/EU); "
        "controller Mapp Digital US, LLC (San Diego) since the 2019 "
        "acquisition"
    )
    sovereignty_notes = (
        "US controller since Mapp Digital's 2019 acquisition of "
        "Webtrekk — CLOUD Act / FISA 702 apply even though collection "
        "is historically EU-hosted. Both detection domains are "
        "documented CNAME-cloaking tails (NextDNS blocklist)."
    )
    canonical_domains = ("webtrekk.net", "wt-eu02.net")
    # CNAME-cloaked tracker → privacy 4.5 (evasion override). security 2.5
    #   (unpinned vendor JS). resilience 2.5 (US analytics/attribution
    #   measurement vendor, replaceable supporting feature; rubric 2.5).
    impact_rating = ImpactRating(privacy=4.5, security=2.5, resilience=2.5)
    impact_notes = {
        "privacy": "A CNAME-cloaked analytics/attribution tracker — "
            "disguised as first-party so it evades blockers and consent "
            "expectations.",
        "security": "First-party-served vendor JavaScript, unpinned.",
        "resilience": "A US measurement vendor — replaceable supporting "
            "feature.",
    }
