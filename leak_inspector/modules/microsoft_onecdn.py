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

"""Microsoft OneCDN static-asset CDN detector.

``*.onecdn.static.microsoft`` is Microsoft's public static-asset CDN for
Microsoft 365 / Outlook-on-the-web (OWA) front-ends — it serves the
JavaScript bundles, CSS, fonts and images for embedded Microsoft
products such as Bookings and Forms (paths like
``/owamail/hashed-v1/...`` and ``/assets/mail/fonts/...``). Observed
host: ``res.public.onecdn.static.microsoft``.

Like the Google and Cloudflare asset hosts (see :mod:`.google_cdn`,
:mod:`.cloudflare_cdn`) it carries no tracking parameters — but it ships
**executable JavaScript** into the embedding page from a **US** company,
so the privacy event is the fetch itself (IP + ``User-Agent`` +
``Referer`` disclosed) and the US jurisdiction feeds the
resilience / sovereignty tally.
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


_HOST_SUFFIX = ".onecdn.static.microsoft"


@register
class MicrosoftOneCDNModule(TrackerModule):
    """Detect Microsoft OneCDN (Microsoft 365 / OWA static-asset CDN)."""

    module_id = "microsoft_onecdn"
    module_name = "Microsoft OneCDN"
    vendor = "Microsoft Corporation"
    legal_jurisdiction = "US"
    data_residency = "Microsoft global edge (fronted by Akamai); US controller"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Asset CDN serving Microsoft 365 / OWA JS/CSS/fonts: privacy 1.0
    #   (presence leak only), security 2.5 (unpinned executable JS into
    #   the embedding context — same class as google_cdn / cloudflare_cdn
    #   2.5), resilience 2.0 (US-controlled asset host, replaceable only by
    #   dropping the embedded Microsoft product).
    impact_rating = ImpactRating(privacy=1.0, security=2.5, resilience=2.0)
    impact_notes = {
        "security": "Serves Microsoft 365 / Outlook-web JavaScript into "
            "the embedding page unpinned — a CDN compromise would run as "
            "the page.",
        "resilience": "A US-controlled asset host that loads only because "
            "an embedded Microsoft product (Bookings / Forms) is present.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return event.host.lower().endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = [
            ParamInfo(
                key=key,
                value=value,
                category=CAT_OTHER,
                meaning="Asset-fetch URL parameter (not a tracking field)",
                privacy_impact=IMPACT_LOW,
                event_index=event.event_id,
            )
            for key, value in event.all_params.items()
        ]
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
