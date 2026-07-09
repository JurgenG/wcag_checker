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

"""Piano Analytics (AT Internet) detector.

AT Internet (Bordeaux, France; the historical XiTi web analytics)
was acquired by Piano Software in 2021; the product line continues
as Piano Analytics. Piano relocated its global headquarters to
Amsterdam (NL) in 2022.

Detection domains:

* ``at-o.net`` — AT Internet's first-party collection domain. The
  NextDNS cname-cloaking blocklist documents it as the canonical
  tail of customer CNAME chains (``stats.<site>`` → ``…at-o.net``) —
  the classic French-market CNAME-cloak deployment.
* ``xiti.com`` — AT Internet's long-standing direct collection
  domain (``logs….xiti.com``).
"""

from __future__ import annotations

from ..impact import ImpactRating
from ._cname_cloak_base import CnameCloakVendorModule
from .base import register


@register
class PianoAnalyticsModule(CnameCloakVendorModule):
    """Detect Piano Analytics / AT Internet collection requests."""

    module_id = "piano_analytics"
    module_name = "Piano Analytics (AT Internet)"
    vendor = "Piano Software B.V."
    legal_jurisdiction = "NL"
    data_residency = (
        "AT Internet collection infrastructure (historically EU/France); "
        "Piano Software B.V. is Amsterdam-headquartered"
    )
    sovereignty_notes = (
        "EU controller: Piano Software relocated its global headquarters "
        "to Amsterdam in 2022, explicitly positioning around GDPR. The "
        "at-o.net collection domain is a documented CNAME-cloaking tail "
        "(NextDNS blocklist) — customers alias stats.<site> to it so the "
        "analytics traffic looks first-party and evades tracker "
        "blocklists, which is an evasion-posture concern independent of "
        "the EU jurisdiction."
    )
    canonical_domains = ("at-o.net", "xiti.com")
    # CNAME-cloaked tracker (AT Internet / Xiti) → 4.5 / 2.5 / 1.5 (EU
    # vendor, NL). See commanders_act for the shared shape.
    impact_rating = ImpactRating(privacy=4.5, security=2.5, resilience=1.5)
    impact_notes = {
        "privacy": "A CNAME-cloaked tracker (AT Internet / Xiti) — "
            "disguised as first-party so it evades blockers and consent "
            "expectations.",
        "security": "First-party-served vendor JavaScript, unpinned.",
        "resilience": "An EU vendor (Netherlands), GDPR-native.",
    }
