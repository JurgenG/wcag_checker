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

"""polyfill-fastly.io detector — Fastly's polyfill.io mirror.

Fastly operates ``polyfill-fastly.io`` as a trusted mirror of the
polyfill.io API after the **June 2024 supply-chain compromise** of
the original ``polyfill.io`` domain. The original domain was
acquired by Funnull (linked to malicious-redirect operations) and
began serving malicious code to >100k sites; Cloudflare and Fastly
stood up mirrors so sites that still depended on the URL could move
without changing their integration.

Recognized host:

* ``polyfill-fastly.io`` — serves ``/v2/polyfill.min.js?features=…``
  and other paths from the original polyfill.io API surface.

The privacy story is dual:

* **Transport** — every fetch sends visitor IP, ``User-Agent``, and
  ``Referer`` to Fastly's edge.
* **Historical risk** — any page still referencing this URL was, at
  some point in its history, fetching JavaScript from a host that
  was actively compromised. Even if Fastly's mirror is now safe, the
  presence of the URL itself is a supply-chain hygiene signal worth
  flagging in an audit.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_CONTENT,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_EXACT = "polyfill-fastly.io"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "features": (CAT_CONTENT,   "Comma-separated polyfill feature list",     IMPACT_LOW),
    "flags":    (CAT_TECHNICAL, "Polyfill feature flags",                    IMPACT_LOW),
    "version":  (CAT_TECHNICAL, "Polyfill library version",                  IMPACT_LOW),
    "ua":       (CAT_TECHNICAL, "User-Agent override (passed in URL)",       IMPACT_LOW),
    "callback": (CAT_TECHNICAL, "JSONP callback name",                       IMPACT_LOW),
    "unknown":  (CAT_TECHNICAL, "Pass-through for unknown features",         IMPACT_LOW),
}


@register
class PolyfillFastlyModule(TrackerModule):
    """Detect polyfill-fastly.io fetches (Fastly's polyfill.io mirror)."""

    module_id = "polyfill_fastly"
    module_name = "polyfill-fastly.io (Fastly)"
    vendor = "Fastly, Inc."
    legal_jurisdiction = "US"
    data_residency = "US (San Francisco, CA HQ); Fastly global edge"
    sovereignty_notes = (
        "US CLOUD Act / FISA 702 apply; URL is the trusted replacement for "
        "polyfill.io after the June 2024 supply-chain compromise of that domain"
    )
    # The proposal anchor: little data, catastrophic governance.
    # privacy 1.0 (a polyfill script host — presence leak, no tracking
    #   payload). security 4.5 (polyfill.io served malware after changing
    #   hands in June 2024 — once-burned infrastructure, the rubric 4.5
    #   "failed governance" line; this Fastly mirror is the trusted
    #   replacement but the dependency class is the same). resilience 2.0
    #   (US, replaceable — polyfills can be bundled/self-hosted).
    impact_rating = ImpactRating(privacy=1.0, security=4.5, resilience=2.0)
    impact_notes = {
        "security": "A polyfill host of the class that served malware "
            "after polyfill.io changed hands in 2024 — once-burned, "
            "governance-failure infrastructure executing in your origin.",
        "resilience": "A US-controlled script host; polyfills can be "
            "bundled / self-hosted instead.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return event.host.lower() == _HOST_EXACT

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized polyfill parameter", IMPACT_LOW)
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
