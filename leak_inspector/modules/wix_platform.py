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

"""Wix platform-infrastructure detector.

A site built on Wix loads its assets, page configuration and code
bundles from Wix-owned CDNs and emits first-party telemetry back to Wix:

* ``*.parastorage.com`` — static asset / font / page-config / Velo code
  CDN (``static``, ``siteassets``, ``bundler-velo`` subdomains),
* ``static.wixstatic.com`` — media (image) CDN,
* ``frog.wix.com`` — the Thunderbolt runtime's telemetry beacon
  (``bolt-performance`` performance and visibility events),
* ``*.wixapps.net`` — Wix app logging (``panorama`` ``bulklog``).

These hosts are Wix's own infrastructure (Wix.com Ltd, an Israeli
company; the observed edge sits on AWS US regions). This module claims
those requests so they no longer fall through to ``unclassified_hosts``,
and classifies their parameters by host role: asset/config fetches are
technical, telemetry-beacon fields are behavioral, with the Wix
session/site identifiers flagged as identifiers.

Scoring (``ImpactRating(1.5, 2.5, 3.0)``): privacy 1.5 — first-party
hosting, but ``frog.wix.com`` carries behavioral telemetry with a
visitor session id, processed by Wix.com Ltd (same class as a hosted
error/telemetry SDK); security 2.5 — ``parastorage.com`` serves the
site's entire runtime JavaScript unpinned into the origin (the asset-CDN
class); resilience 3.0 — the whole site is locked to a single foreign
SaaS that cannot be self-hosted or swapped without rebuilding, deeper
lock-in than a replaceable asset CDN.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
    CAT_IDENTIFIER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


#: Wix-owned host suffixes. ``parastorage.com`` / ``wixstatic.com`` /
#: ``wixapps.net`` are used exclusively by Wix infrastructure.
_HOST_SUFFIXES = (".parastorage.com", ".wixstatic.com", ".wixapps.net")

#: Exact telemetry-beacon host (the Thunderbolt runtime's performance
#: endpoint). ``www.wix.com`` and the editor live elsewhere on
#: ``wix.com``, so we match this host exactly rather than by suffix.
_TELEMETRY_HOST = "frog.wix.com"

#: Telemetry-beacon parameter keys that identify the Wix site or the
#: visitor's session.
_IDENTIFIER_KEYS = frozenset({
    "msid",          # metaSiteId — the Wix site identifier
    "session_id",    # per-session identifier
    "vsi",           # visitor session id
    "mpaSessionId",  # multi-page-application session id
    "svSession",     # Wix visitor cookie value
    "vid",           # visitor id
})


@register
class WixPlatformModule(TrackerModule):
    """Detect Wix platform CDN and first-party telemetry requests."""

    module_id = "wix_platform"
    module_name = "Wix"
    vendor = "Wix.com Ltd"
    legal_jurisdiction = "IL"
    data_residency = "AWS edge/CDN (US regions observed); Wix.com Ltd (Israel)"
    sovereignty_notes = (
        "First-party hosting platform; visitor telemetry is processed by Wix."
    )
    impact_rating = ImpactRating(privacy=1.5, security=2.5, resilience=3.0)
    impact_notes = {
        "privacy": "frog.wix.com carries behavioral telemetry with a visitor "
            "session id, processed by Wix.com Ltd (Israel).",
        "security": "parastorage.com serves the site's entire runtime "
            "JavaScript unpinned into the origin — a platform compromise "
            "would run as the site.",
        "resilience": "The whole site is locked to a single foreign SaaS that "
            "cannot be self-hosted or swapped without rebuilding.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host == _TELEMETRY_HOST:
            return True
        return any(host.endswith(suffix) for suffix in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        telemetry = self._is_telemetry(event.host)
        params = [
            self._classify(key, value, telemetry, event.event_id)
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

    @staticmethod
    def _is_telemetry(host: str) -> bool:
        host = host.lower()
        return host == _TELEMETRY_HOST or host.endswith(".wixapps.net")

    @staticmethod
    def _classify(
        key: str, value: str, telemetry: bool, event_id: int
    ) -> ParamInfo:
        if telemetry:
            if key in _IDENTIFIER_KEYS:
                return ParamInfo(
                    key=key, value=value, category=CAT_IDENTIFIER,
                    meaning="Wix site/visitor session identifier",
                    privacy_impact=IMPACT_MEDIUM, event_index=event_id,
                )
            return ParamInfo(
                key=key, value=value, category=CAT_BEHAVIORAL,
                meaning="Wix first-party telemetry field",
                privacy_impact=IMPACT_LOW, event_index=event_id,
            )
        return ParamInfo(
            key=key, value=value, category=CAT_TECHNICAL,
            meaning="Wix platform asset/config parameter",
            privacy_impact=IMPACT_LOW, event_index=event_id,
        )