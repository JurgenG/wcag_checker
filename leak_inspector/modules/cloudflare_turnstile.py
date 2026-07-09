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

"""Cloudflare Turnstile detector.

Turnstile is Cloudflare's CAPTCHA-replacement / bot-challenge widget —
same product class as Google reCAPTCHA. It loads a JS bundle, runs a
sequence of device-fingerprint probes (timing, hardware, browser
quirks), scores the visitor for "humanness", and returns a token to
the embedding page for server-side verification.

All Turnstile traffic flows through ``challenges.cloudflare.com``:

* ``/turnstile/v0/api.js`` — the loader script.
* ``/turnstile/v0/embed/...`` — the iframe widget.
* Various RPC endpoints under ``/turnstile/v0/`` — challenge issuance
  and result reporting.

The actual fingerprint signals travel in the POST bodies and Cloudflare
challenge tokens — none of which is visible to v1.0 capture. What we
can surface from the wire is the per-customer ``sitekey``, the challenge
ID, and the fact that fingerprinting is happening at all.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
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


_TURNSTILE_HOST = "challenges.cloudflare.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    # --- per-customer identifier ---
    "sitekey": (CAT_TECHNICAL,  "Turnstile public site key (per-customer)",     IMPACT_LOW),
    "k":       (CAT_TECHNICAL,  "Site key (short form)",                         IMPACT_LOW),
    # --- per-challenge correlation ---
    "c":   (CAT_IDENTIFIER, "Per-challenge correlation ID",                      IMPACT_MEDIUM),
    "cid": (CAT_IDENTIFIER, "Challenge instance ID",                             IMPACT_MEDIUM),
    "ts":  (CAT_TECHNICAL,  "Client-side timestamp",                             IMPACT_LOW),
    # --- widget configuration ---
    "render":   (CAT_TECHNICAL,  "Render mode (explicit / auto)",                IMPACT_LOW),
    "size":     (CAT_TECHNICAL,  "Widget size",                                  IMPACT_LOW),
    "theme":    (CAT_TECHNICAL,  "Widget theme (light / dark / auto)",           IMPACT_LOW),
    "action":   (CAT_BEHAVIORAL, "Action label set by the embedding page",       IMPACT_LOW),
    "cdata":    (CAT_BEHAVIORAL, "Custom data attached to the challenge",        IMPACT_LOW),
    "callback": (CAT_TECHNICAL,  "JS callback name",                             IMPACT_LOW),
    "language": (CAT_TECHNICAL,  "Widget language",                              IMPACT_LOW),
    # --- iframe embed context ---
    "origin":   (CAT_BEHAVIORAL, "Embedding-page origin",                        IMPACT_LOW),
    "hl":       (CAT_TECHNICAL,  "Host language hint",                           IMPACT_LOW),
    # --- protocol / dispatch ---
    "v":   (CAT_TECHNICAL, "Turnstile protocol version",                         IMPACT_LOW),
    "ift": (CAT_TECHNICAL, "Iframe-load type",                                   IMPACT_LOW),
}


@register
class CloudflareTurnstileModule(TrackerModule):
    """Detect Cloudflare Turnstile (CAPTCHA / bot-challenge) traffic."""

    module_id = "cloudflare_turnstile"
    module_name = "Cloudflare Turnstile"
    vendor = "Cloudflare, Inc."
    legal_jurisdiction = "US"
    data_residency = "Cloudflare global edge (closest PoP — typically EU edge for EU visitors)"
    sovereignty_notes = "US CLOUD Act applies regardless of which edge PoP serves the visitor"
    # Privacy-first bot challenge (no behavioural fingerprinting marketed):
    #   privacy 1.5 (challenge telemetry only; rubric 1.5, below hCaptcha).
    #   security 1.5 (sandboxed iframe). resilience 2.5 (US, replaceable
    #   supporting feature — rubric 2.5).
    impact_rating = ImpactRating(privacy=1.5, security=1.5, resilience=2.5)
    impact_notes = {
        "privacy": "A privacy-first bot challenge — challenge telemetry "
            "only, no behavioural fingerprinting marketed.",
        "security": "Runs in a sandboxed cross-origin iframe.",
        "resilience": "A US vendor for a replaceable supporting feature.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return event.host.lower() == _TURNSTILE_HOST

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Cloudflare Turnstile parameter", IMPACT_LOW)
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
