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

"""Statsig (feature-flagging / experimentation) detector.

Statsig, Inc. (Seattle, US) provides feature-flagging, A/B experiments
and product analytics. It **rotates its endpoint domains to evade
tracker/ad-blockers** (observed: ``featureassets.org``,
``prodregistryv2.org``; more in the wild), so this module matches on
Statsig's **stable client-SDK API signature instead of the host**:

* the path is ``/v1/initialize`` (fetch config), ``/v1/rgstr`` (the event
  log beacon) or ``/v1/log_event``, **and**
* the query carries ``k=client-…`` (the Statsig client key), ``st`` (SDK
  type, e.g. ``javascript-client``) and ``sv`` (SDK version).

This signature is invariant across whatever domain Statsig serves from
today, and catches the SDK even when proxied behind a first-party CNAME —
the same host-agnostic strategy the Sentry module uses for self-hosted
collectors.

Scoring (``ImpactRating(4.5, 2.0, 2.5)``): privacy 4.5 — the rubric's
**evasion** band; blocker-evading domain rotation is rated at the top
"regardless of payload". security 2.0 — the SDK runs in-origin but adds
no separate unpinned script of its own (it rides inside the host
platform's bundle). resilience 2.5 — a US dependency that, when embedded
by a platform, cannot be removed without leaving it.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


#: Statsig client-SDK API paths (stable across the domain rotation).
_STATSIG_PATHS = ("/v1/initialize", "/v1/rgstr", "/v1/log_event")

#: Per-parameter classification; ``k`` is the Statsig *project* key (not a
#: visitor id), ``sid`` is the visitor session id.
_PARAMS: dict[str, tuple[str, str, str]] = {
    "sid": (CAT_IDENTIFIER, "Statsig session identifier", IMPACT_MEDIUM),
    "k":   (CAT_TECHNICAL,  "Statsig client SDK key (identifies the Statsig project)", IMPACT_LOW),
    "st":  (CAT_TECHNICAL,  "Statsig SDK type (e.g. javascript-client)", IMPACT_LOW),
    "sv":  (CAT_TECHNICAL,  "Statsig SDK version", IMPACT_LOW),
    "t":   (CAT_TECHNICAL,  "Request timestamp", IMPACT_LOW),
}


@register
class StatsigModule(TrackerModule):
    """Detect Statsig client-SDK traffic by its host-agnostic API signature."""

    module_id = "statsig"
    module_name = "Statsig"
    vendor = "Statsig, Inc."
    legal_jurisdiction = "US"
    data_residency = "US (Seattle, WA HQ); global serving"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Blocker-evading product-analytics SDK (rubric evasion band): privacy
    #   4.5 (domain rotation to defeat blockers — rated at top regardless of
    #   payload), security 2.0 (in-origin SDK, no separate unpinned fetch of
    #   its own), resilience 2.5 (US; platform-embedded, removable only by
    #   leaving the platform).
    impact_rating = ImpactRating(privacy=4.5, security=2.0, resilience=2.5)
    impact_notes = {
        "privacy": "Rotates its endpoint domains to evade blockers — a "
            "deliberate evasion technique, rated at the top regardless of "
            "the (session-tied) payload it carries.",
        "security": "The SDK runs in-origin and exfiltrates obfuscated "
            "payloads, but adds no separate unpinned script of its own.",
        "resilience": "A US dependency; when embedded by a platform it "
            "cannot be removed without leaving the platform.",
    }

    def matches(self, event: RequestEvent) -> bool:
        path = urlparse(event.url or "").path
        if not any(path.endswith(p) for p in _STATSIG_PATHS):
            return False
        params = event.query_params
        return (
            "st" in params
            and "sv" in params
            and params.get("k", "").startswith("client-")
        )

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Statsig SDK parameter", IMPACT_LOW)
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
