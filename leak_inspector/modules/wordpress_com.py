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

"""WordPress.com / Jetpack (Automattic) platform detector.

Automattic's infrastructure backs both WordPress.com-hosted sites and
the Jetpack plugin on self-hosted WordPress. Its observed footprint:

* ``*.wp.com`` — the platform CDN and services: ``c0``/``s0`` static
  assets, ``i0``/``i1``/``i2`` the Photon image CDN, ``fonts`` /
  ``fonts-api`` web fonts, ``widgets``,
* ``pixel.wp.com`` / ``stats.wp.com`` — the WordPress.com / Jetpack
  page-view stats beacon (``g.gif`` with ``blog`` / ``post`` / ``ref`` /
  ``fcp`` …),
* ``*.gravatar.com`` — Automattic's avatar CDN,
* ``public-api.wordpress.com`` / ``r-login.wordpress.com`` — the
  WordPress.com API and remote-login (SSO) endpoints.

This module claims those Automattic-owned requests so they no longer
fall through to ``unclassified_hosts``, classifying the stats-beacon
fields as behavioral and the asset/Photon parameters as technical. It
deliberately does NOT claim a hosted site's own ``<site>.wordpress.com``
content host — that is first-party.

Scoring (``ImpactRating(1.5, 2.5, 2.0)``): privacy 1.5 — the stats
beacon records page views (first-party analytics by Automattic, no
durable cross-site profile); security 2.5 — ``wp.com`` serves runtime
JavaScript unpinned into the origin; resilience 2.0 — a foreign-hosted
CDN/stats dependency. Resilience is held at the CDN level rather than
full-hosting lock-in because ``wp.com`` is shared with Jetpack on
self-hosted WordPress, so full lock-in cannot be certainly asserted.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
    CAT_CONTENT,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIXES = (".wp.com", ".gravatar.com")
_HOST_EXACT = frozenset({"public-api.wordpress.com", "r-login.wordpress.com"})


#: Non-technical overrides on the stats beacon; everything else (Photon
#: image params, fonts, blog/post/host identifiers, …) is platform
#: technical metadata.
_PARAMS: dict[str, tuple[str, str, str]] = {
    "fcp": (CAT_BEHAVIORAL, "First-contentful-paint timing (page-performance telemetry)", IMPACT_LOW),
    "ref": (CAT_CONTENT,    "Referring page URL the visitor came from", IMPACT_MEDIUM),
}


@register
class WordPressComModule(TrackerModule):
    """Detect WordPress.com / Jetpack (Automattic) platform traffic."""

    module_id = "wordpress_com"
    module_name = "WordPress.com / Jetpack"
    vendor = "Automattic, Inc."
    legal_jurisdiction = "US"
    data_residency = "US (Automattic); global CDN edge"
    sovereignty_notes = "First-party platform/CDN; US CLOUD Act applies"
    impact_rating = ImpactRating(privacy=1.5, security=2.5, resilience=2.0)
    impact_notes = {
        "privacy": "pixel.wp.com records page views (Automattic first-party "
            "stats); session-level, no durable cross-site profile.",
        "security": "wp.com serves runtime JavaScript unpinned into the "
            "origin — a platform compromise would run as the site.",
        "resilience": "A foreign-hosted (US) CDN/stats dependency.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _HOST_EXACT:
            return True
        return any(host.endswith(suffix) for suffix in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_TECHNICAL, "WordPress.com / Jetpack platform parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key, value=value, category=category, meaning=meaning,
                    privacy_impact=impact, event_index=event.event_id,
                )
            )
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
