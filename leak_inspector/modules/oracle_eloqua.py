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

"""Oracle Eloqua detector.

Eloqua is Oracle's B2B marketing-automation platform. Detection
domains:

* ``eloqua.com`` — application + tracking endpoints
  (``s<site-id>.t.eloqua.com`` visitor tracking); ``hs.eloqua.com``
  is the documented CNAME-cloaking tail (NextDNS blocklist).
* ``en25.com`` — Eloqua's long-standing asset/tracking domain
  (``img.en25.com``).
"""

from __future__ import annotations

from ..impact import ImpactRating
from ._cname_cloak_base import CnameCloakVendorModule
from .base import register


@register
class OracleEloquaModule(CnameCloakVendorModule):
    """Detect Oracle Eloqua marketing-automation requests."""

    module_id = "oracle_eloqua"
    module_name = "Oracle Eloqua"
    vendor = "Oracle Corporation"
    legal_jurisdiction = "US"
    data_residency = "Oracle-operated infrastructure (US-primary)"
    sovereignty_notes = (
        "US controller — CLOUD Act / FISA 702 apply; Schrems II "
        "transfer analysis required. hs.eloqua.com is a documented "
        "CNAME-cloaking tail (NextDNS blocklist). Marketing-automation "
        "context means visitors arriving from Eloqua-sent email are "
        "identified individuals, not pseudonyms."
    )
    canonical_domains = ("eloqua.com", "en25.com")
    # CNAME-cloaked tracker → privacy 4.5 (evasion override). security 2.5
    #   (unpinned vendor JS). resilience 3.0 (Oracle enterprise marketing
    #   cloud — operational dependence + heavy US-vendor lock-in; rubric
    #   3.0).
    impact_rating = ImpactRating(privacy=4.5, security=2.5, resilience=3.0)
    impact_notes = {
        "privacy": "A CNAME-cloaked marketing tracker — disguised as "
            "first-party so it evades blockers and consent expectations.",
        "security": "First-party-served vendor JavaScript, unpinned.",
        "resilience": "Oracle's enterprise marketing cloud — operational "
            "dependence plus heavy US-vendor lock-in.",
    }
