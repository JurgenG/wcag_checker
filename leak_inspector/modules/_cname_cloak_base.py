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

"""Shared base for CNAME-cloaking vendor detectors.

These vendors are encountered primarily through *first-party-looking
subdomains* of the visited site that CNAME to the vendor's canonical
collection domain (mappings documented by the NextDNS cname-cloaking
blocklist). The module's job is therefore twofold:

* let the generic CNAME-cloak detector in the analysis runner
  attribute a chain whose canonical tail lands on the vendor's
  domains, and
* claim the (rarer) direct hit on those domains.

Parameter-level classification is intentionally generic
(``CAT_OTHER``): each vendor has its own undocumented parameter
dictionary, and per CLAUDE.md we don't speculate. The privacy weight
of a cloaked hit comes from the *fact* of the evasion (the
``(cname-cloak)`` marker → evasion deduction) and the vendor's
jurisdiction (→ resilience), not from guessed per-key meanings.
"""

from __future__ import annotations

from ..events import RequestEvent
from ._public_sector_base import host_matches_suffix_set
from .base import (
    CAT_OTHER,
    Hit,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
)


class CnameCloakVendorModule(TrackerModule):
    """Host-suffix detector for a CNAME-cloaking vendor.

    Subclasses set the usual :class:`TrackerModule` identity fields
    plus :attr:`canonical_domains` — the registrable domains the
    vendor's CNAME chains terminate on (and any documented direct
    collection domains).
    """

    #: Registrable domains matched as ``host == d or host.endswith("." + d)``.
    canonical_domains: tuple[str, ...] = ()

    def matches(self, event: RequestEvent) -> bool:
        return host_matches_suffix_set(
            event.host, suffix_matches=self.canonical_domains,
        )

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            params.append(ParamInfo(
                key=key,
                value=value,
                category=CAT_OTHER,
                meaning=f"Unclassified {self.module_name} parameter",
                privacy_impact=IMPACT_LOW,
                event_index=event.event_id,
            ))
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
