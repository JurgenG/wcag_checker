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

"""Cloudflare Zaraz (server-side tag manager) detector.

Zaraz executes third-party tools (GA4, Meta Pixel, TikTok, …) at
Cloudflare's edge instead of in the browser. The browser only talks
to the site's *own* domain under Cloudflare's reserved path
namespace — the init script is documented as ``/cdn-cgi/zaraz/i.js``
(Cloudflare "Load Zaraz manually" guide), and event traffic rides
the same ``/cdn-cgi/zaraz/`` prefix. Nothing else legitimately lives
under ``/cdn-cgi/`` — it is Cloudflare's reserved namespace on every
proxied site.

What this module can and cannot see:

* It CAN flag that the operator runs a server-side tag manager —
  requests under ``/cdn-cgi/zaraz/`` carry visitor data (IP, UA,
  page context, configured event payloads) to Cloudflare's edge,
  which forwards them to the configured vendors server-side.
* It CANNOT name those downstream vendors: that configuration is
  server-side only. A Zaraz hit therefore *understates* the real
  third-party graph — treat it as a marker that browser-visible
  analysis is structurally incomplete for this site.

Known limitation: Zaraz endpoints are customizable (Settings →
custom endpoints); operators that move them off ``/cdn-cgi/zaraz/``
evade this fingerprint.

Hits carry the HIGH-impact ``(fp-proxy)`` marker — the same one the
Google FP-Mode module uses — so the privacy/resilience scoring
overrides count this first-party-looking traffic as the third-party
flow it is.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_HTTP_TRAFFIC,
    CAT_OTHER,
    Hit,
    IMPACT_HIGH,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
    register,
)


#: Cloudflare's reserved Zaraz path namespace on proxied sites.
_ZARAZ_PATH_PREFIX = "/cdn-cgi/zaraz/"


@register
class CloudflareZarazModule(TrackerModule):
    """Detect Cloudflare Zaraz server-side tag-manager traffic."""

    module_id = "cloudflare_zaraz"
    module_name = "Cloudflare Zaraz (server-side tag manager)"
    vendor = "Cloudflare, Inc."
    legal_jurisdiction = "US"
    data_residency = (
        "Cloudflare edge (global anycast); downstream tool vendors "
        "receive the data server-side and are not browser-visible"
    )
    sovereignty_notes = (
        "Cloudflare, Inc. is the US-incorporated edge processor — "
        "CLOUD Act / FISA 702 apply to the event stream. The vendors "
        "Zaraz forwards to (GA4, Meta, TikTok, …) are configured "
        "server-side and invisible to a browser capture, so this hit "
        "understates the real third-party graph rather than bounding it."
    )
    # Tag manager: privacy 1.5 (the loader ships little itself; the tags
    #   it forwards are scored as their own vendors). security 3.0 (its
    #   function is loading further third-party code — rubric code-loader
    #   3.0; edge-executed, but still operator-delegated arbitrary tags).
    # resilience 2.5 (US Cloudflare, replaceable — rubric 2.5).
    impact_rating = ImpactRating(privacy=1.5, security=3.0, resilience=2.5)
    impact_notes = {
        "privacy": "A server-side tag manager — ships little itself; the "
            "vendors it forwards to are scored separately.",
        "security": "Its function is to load further third-party code — a "
            "compromise or mis-set tag can run anything in your origin.",
        "resilience": "A US-hosted control layer over what runs on your "
            "pages.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return urlparse(event.url).path.startswith(_ZARAZ_PATH_PREFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = [ParamInfo(
            key="(fp-proxy) host",
            value=event.host,
            category=CAT_HTTP_TRAFFIC,
            meaning=(
                "Server-side tag manager on the operator's own domain — "
                "visitor data is forwarded to third-party vendors at "
                "Cloudflare's edge, invisible to the browser. The "
                "first-party-looking host evades tracker blocklists and "
                "third-party-cookie restrictions."
            ),
            privacy_impact=IMPACT_HIGH,
            event_index=event.event_id,
        )]
        for key, value in event.all_params.items():
            params.append(ParamInfo(
                key=key,
                value=value,
                category=CAT_OTHER,
                meaning="Zaraz event parameter — unclassified",
                privacy_impact=IMPACT_LOW,
                event_index=event.event_id,
            ))
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
