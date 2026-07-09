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

"""Browsealoud (Texthelp) text-to-speech detector.

Browsealoud is Texthelp Ltd's (Northern Ireland, UK) text-to-speech /
reading-support accessibility widget, embedded on public-sector sites.
Like ReadSpeaker it sends the page text to the vendor to synthesise
speech, and runs unpinned third-party JavaScript in the origin.

Notable: Browsealoud was the vector of the **February 2018 supply-chain
attack** — a compromised Browsealoud script injected the Coinhive
crypto-miner into 4,000+ sites including the UK ICO and many government
bodies. The product was later folded into Texthelp's ReachDeck; the
legacy ``browsealoud`` hosts remain in use.

Recognized hosts: any subdomain of ``browsealoud.com`` and the regional
``browsealoud.nl``. Query parameters, when present, are surfaced
unclassified.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_OTHER,
    Hit,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIXES: tuple[str, ...] = (".browsealoud.com", ".browsealoud.nl")
_HOST_EXACTS: frozenset[str] = frozenset({"browsealoud.com", "browsealoud.nl"})


@register
class BrowsealoudModule(TrackerModule):
    """Detect Browsealoud / Texthelp text-to-speech accessibility traffic."""

    module_id = "browsealoud"
    module_name = "Browsealoud (Texthelp)"
    vendor = "Texthelp Ltd"
    legal_jurisdiction = "UK"
    data_residency = "UK (Texthelp, Northern Ireland); global serving infrastructure"
    sovereignty_notes = (
        "UK controller — a non-EU adequacy jurisdiction. Browsealoud was the "
        "vector of the February 2018 Coinhive supply-chain attack on 4,000+ "
        "sites (incl. the UK ICO and government bodies)"
    )
    # Accessibility TTS widget (UK vendor) with a documented supply-chain
    #   history: privacy 1.5 (sends page text to synthesise speech;
    #   contained, not cross-site ad tracking), security 2.5 (unpinned
    #   third-party JS in the origin — this is the product that the 2018
    #   Coinhive compromise actually rode), resilience 1.5 (UK, non-EU
    #   adequacy).
    impact_rating = ImpactRating(privacy=1.5, security=2.5, resilience=1.5)
    impact_notes = {
        "privacy": "To read the page aloud, the widget sends the page text "
            "to Texthelp — contained, not a cross-site tracker.",
        "security": "Runs unpinned third-party JavaScript in your origin — "
            "and is the exact product whose 2018 compromise injected a "
            "crypto-miner into thousands of government sites.",
        "resilience": "UK-based — a non-EU adequacy jurisdiction.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _HOST_EXACTS:
            return True
        return any(host.endswith(suffix) for suffix in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            params.append(
                ParamInfo(
                    key=key,
                    value=value,
                    category=CAT_OTHER,
                    meaning="Browsealoud parameter — unclassified",
                    privacy_impact=IMPACT_LOW,
                    event_index=event.event_id,
                )
            )
        return Hit(
            module_id=self.module_id,
            module_name=self.module_name,
            url=event.url,
            host=event.host,
            method=event.method,
            response_status=event.response_status,
            started_at=event.timestamp,
            params=params,
            events=[event.event_id],
        )
