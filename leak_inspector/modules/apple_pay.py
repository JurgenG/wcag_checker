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

"""Apple Pay on the Web detector.

Apple Pay on the Web lets merchants accept Apple Pay in Safari and other
supported web contexts using Apple-provided JavaScript APIs. This module
recognizes the public Apple Pay JS / Wallet SDK CDN host observed in
captures.

Recognized hosts:

* ``applepay.cdn-apple.com`` — Apple Pay JS, Apple Wallet SDK and
  Apple Pay button assets (for example
  ``/jsapi/1.latest/apple-pay-sdk.js``).

Privacy note: these SDK requests are usually asset loads rather than
tracking beacons, and the observed endpoints do not carry query/body
parameters. They still disclose the ambient HTTP surface (visitor IP,
``User-Agent`` and ``Referer``) to Apple when a merchant page loads Apple
Pay support. Path-derived fields are emitted as LOW-impact technical
metadata so reports can distinguish SDK asset loads from unclassified
third-party hosts.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_EXACT = "applepay.cdn-apple.com"
_JSAPI_PREFIX = "/jsapi/"


_PARAMS: dict[str, tuple[str, str, str]] = {
    # --- technical / SDK plumbing ---
    "version": (CAT_TECHNICAL, "Apple Pay JS SDK version selector", IMPACT_LOW),
    "asset":   (CAT_TECHNICAL, "Apple Pay / Wallet JavaScript asset name", IMPACT_LOW),
}


def _path_params(path: str) -> dict[str, str]:
    """Extract stable technical fields from Apple Pay JS SDK asset paths."""

    if not path.startswith(_JSAPI_PREFIX):
        return {}

    # /jsapi/1.latest/apple-pay-sdk.js -> version=1.latest, asset=apple-pay-sdk.js
    parts = path[len(_JSAPI_PREFIX):].strip("/").split("/")
    if len(parts) < 2:
        return {}

    return {
        "version": parts[0],
        "asset": parts[-1],
    }


@register
class ApplePayModule(TrackerModule):
    """Detect Apple Pay on the Web SDK / button asset traffic."""

    module_id = "apple_pay"
    module_name = "Apple Pay on the Web"
    vendor = "Apple Inc."
    legal_jurisdiction = "US"
    data_residency = "Apple global infrastructure"
    sovereignty_notes = (
        "US CLOUD Act applies. Apple Pay SDK requests observed here are asset "
        "loads, not advertising beacons, but they still disclose IP address, "
        "User-Agent and Referer to Apple as ambient HTTP traffic."
    )
    # Payment method: privacy 1.5 (payment-intent context to Apple, but
    #   tokenized/privacy-preserving by design — rubric 1.5). security 1.5
    #   (sandboxed payment sheet). resilience 2.5 (US Apple, a payment
    #   supporting feature — rubric 2.5).
    impact_rating = ImpactRating(privacy=1.5, security=1.5, resilience=2.5)
    impact_notes = {
        "privacy": "Payment-intent context reaches Apple, but tokenised / "
            "privacy-preserving by design.",
        "security": "Runs in a sandboxed payment sheet.",
        "resilience": "A US (Apple) payment supporting feature.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return event.host.lower() == _HOST_EXACT

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []

        # Apple Pay JS asset URLs commonly have no query string. Emit
        # path-derived technical fields so reports can explain what was loaded.
        observed = _path_params(urlparse(event.url).path)
        observed.update(event.all_params)

        for key, value in observed.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Apple Pay parameter", IMPACT_LOW)
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
