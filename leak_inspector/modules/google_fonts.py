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

"""Google Fonts detector.

Catches requests to:

* ``fonts.googleapis.com`` — the CSS API that resolves a font family to a
  stylesheet of ``@font-face`` rules.
* ``fonts.gstatic.com`` — the font binary host the stylesheet then loads.

Google Fonts carries very few query parameters; the real leak is the
request itself. Loading a font hands Google the visitor's IP address,
``User-Agent``, and ``Referer`` — useful for behavioral linkage even
though no explicit identifier is sent.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_CONTENT,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOSTS = {"fonts.googleapis.com", "fonts.gstatic.com"}


_PARAMS: dict[str, tuple[str, str, str]] = {
    "family":   (CAT_CONTENT,   "Requested font family/families",            IMPACT_MEDIUM),
    "display":  (CAT_TECHNICAL, "font-display CSS strategy",                 IMPACT_LOW),
    "subset":   (CAT_TECHNICAL, "Character subset (e.g. latin, cyrillic)",   IMPACT_LOW),
    "text":     (CAT_CONTENT,   "Inline glyph subset — may echo page text",  IMPACT_HIGH),
    "effect":   (CAT_TECHNICAL, "Font effect filter",                        IMPACT_LOW),
    "lang":     (CAT_TECHNICAL, "Requested language subset",                 IMPACT_LOW),
}


@register
class GoogleFontsModule(TrackerModule):
    """Detect Google Fonts CSS API and font binary fetches."""

    module_id = "google_fonts"
    module_name = "Google Fonts"
    vendor = "Google LLC"
    legal_jurisdiction = "US"
    data_residency = "Google global CDN"
    sovereignty_notes = "Each font request leaks visitor IP + User-Agent + Referer to Google (no analytics payload, but a per-page transfer to a US controller)"
    # privacy 1.0: presence-of-visit leak (IP/UA/Referer) to an unrelated
    #   US controller, no identifier set, nothing stored (rubric privacy
    #   1.0). security 1.0: fonts.googleapis.com returns a *stylesheet* —
    #   external CSS is style-capable (rubric security 1.0), above static
    #   binaries (0.5). resilience 2.0: a US controller for a trivially
    #   self-hostable cosmetic asset — pure habit-dependency (rubric 2.0).
    impact_rating = ImpactRating(privacy=1.0, security=1.0, resilience=2.0)
    impact_notes = {
        "resilience": "A US-controlled host for fonts that are trivially "
            "self-hostable — a dependency of pure habit.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return event.host.lower() in _HOSTS

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Google Fonts parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key,
                    value=value,
                    category=category,
                    meaning=meaning,
                    privacy_impact=impact,
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
