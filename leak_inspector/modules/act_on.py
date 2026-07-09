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

"""Act-On detector.

Act-On Software, Inc. (Portland, Oregon) is a US marketing-automation
platform. The CNAME-cloaking literature (APNIC measurement study,
NextDNS blocklist) names it among the top cloaking trackers:
customers alias a first-party subdomain to ``actonservice.com`` /
``actonsoftware.com`` for email-to-web visitor tracking.
"""

from __future__ import annotations

from ..impact import ImpactRating
from ._cname_cloak_base import CnameCloakVendorModule
from .base import register


@register
class ActOnModule(CnameCloakVendorModule):
    """Detect Act-On marketing-automation requests (usually CNAME-cloaked)."""

    module_id = "act_on"
    module_name = "Act-On"
    vendor = "Act-On Software, Inc."
    legal_jurisdiction = "US"
    data_residency = "Act-On-operated infrastructure (US-primary)"
    sovereignty_notes = (
        "US controller — CLOUD Act / FISA 702 apply; Schrems II "
        "transfer analysis required. Both detection domains are "
        "documented CNAME-cloaking tails (NextDNS blocklist), so a hit "
        "combines extra-territorial exposure with deliberate "
        "tracker-blocklist evasion. Marketing-automation context means "
        "the visitor is often email-identified (link-click tokens), "
        "not merely pseudonymous."
    )
    canonical_domains = ("actonservice.com", "actonsoftware.com")
    # CNAME-cloaked tracker → privacy 4.5 (deliberate evasion overrides
    #   the payload; rubric privacy 4.5). security 2.5 (first-party-served
    #   vendor JS, unpinned). resilience 3.0 (US marketing-automation
    #   outreach platform — operational dependence, like HubSpot; rubric
    #   3.0). Email-identification (link-click tokens) could reach privacy
    #   5.0, but that needs PII observed on the wire (certainty rule).
    impact_rating = ImpactRating(privacy=4.5, security=2.5, resilience=3.0)
    impact_notes = {
        "privacy": "A CNAME-cloaked marketing tracker — disguised as "
            "first-party so it evades blockers and consent expectations.",
        "security": "First-party-served vendor JavaScript, unpinned.",
        "resilience": "A US marketing-automation outreach platform — "
            "operational dependence.",
    }
