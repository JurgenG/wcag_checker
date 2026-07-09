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

"""Google reCAPTCHA detector.

reCAPTCHA is Google's bot-challenge / fingerprinting product (v2 +
v3 + Enterprise). Same product class as :mod:`.cloudflare_turnstile`
and :mod:`.hcaptcha`: collect a sequence of device-fingerprint probes
(timing, hardware, mouse-movement patterns, browser quirks) and score
the visitor for "humanness".

Recognized URL surface:

* ``www.google.com/recaptcha/...`` — primary loader + iframe + RPC.
* ``www.gstatic.com/recaptcha/...`` — static asset delivery.
* ``www.recaptcha.net/recaptcha/...`` — alternative host (used as a
  drop-in replacement for sites where ``www.google.com`` is blocked,
  e.g. in China).

Path is matched specifically (``/recaptcha/`` prefix) so we do not
claim unrelated Google search / gstatic traffic.

The actual fingerprint signals travel in POST bodies, encrypted tokens,
and a sequence of timing observations that v1.0 capture cannot record.
The *presence* of the requests + the public ``k`` (site key) is what we
can surface.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
    CAT_CONTENT,
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


_PATH_GATED_HOSTS: frozenset[str] = frozenset({
    "www.google.com",
    "www.gstatic.com",
})

_RECAPTCHA_ONLY_HOSTS: frozenset[str] = frozenset({
    "www.recaptcha.net",
    "recaptcha.net",
})

_RECAPTCHA_PATH_PREFIX = "/recaptcha/"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "k":         (CAT_TECHNICAL,  "reCAPTCHA public site key (per-customer)",  IMPACT_LOW),
    "render":    (CAT_TECHNICAL,  "Render mode or explicit site key (v3 form)", IMPACT_LOW),
    "c":         (CAT_IDENTIFIER, "Per-challenge correlation token",            IMPACT_MEDIUM),
    "co":        (CAT_CONTENT,    "Embedding-page origin (base64-encoded)",    IMPACT_MEDIUM),
    "host":      (CAT_CONTENT,    "Embedding-page host context",               IMPACT_LOW),
    "action":    (CAT_BEHAVIORAL, "Action label set by the embedding page",    IMPACT_LOW),
    "size":      (CAT_TECHNICAL, "Widget size (normal / compact / invisible)", IMPACT_LOW),
    "theme":     (CAT_TECHNICAL, "Widget theme (light / dark)",                IMPACT_LOW),
    "badge":     (CAT_TECHNICAL, "Badge position (bottomright / bottomleft / inline)", IMPACT_LOW),
    "tabindex":  (CAT_TECHNICAL, "Widget tab-index",                           IMPACT_LOW),
    "type":      (CAT_TECHNICAL, "Challenge type (image / audio)",             IMPACT_LOW),
    "ar":        (CAT_TECHNICAL, "Auto-render flag",                           IMPACT_LOW),
    "cb":        (CAT_TECHNICAL, "JS callback identifier",                     IMPACT_LOW),
    "callback":  (CAT_TECHNICAL, "JS callback name",                           IMPACT_LOW),
    "hl":        (CAT_TECHNICAL, "Widget language",                            IMPACT_LOW),
    "v":         (CAT_TECHNICAL, "reCAPTCHA build identifier (base64-encoded token, not a numeric version)", IMPACT_LOW),
    "onload":    (CAT_TECHNICAL, "Onload-callback name",                       IMPACT_LOW),
    "p":         (CAT_TECHNICAL, "Challenge-RPC payload identifier",           IMPACT_LOW),
    "reason":    (CAT_TECHNICAL, "RPC reason code",                            IMPACT_LOW),
    "anchor-ms": (CAT_TECHNICAL, "Anchor-ready timeout (ms)",                  IMPACT_LOW),
    "execute-ms": (CAT_TECHNICAL, "Challenge-execute timeout (ms)",            IMPACT_LOW),
}


@register
class RecaptchaModule(TrackerModule):
    """Detect Google reCAPTCHA loader, iframe, and RPC traffic."""

    module_id = "recaptcha"
    module_name = "Google reCAPTCHA"
    vendor = "Google LLC"
    legal_jurisdiction = "US"
    data_residency = "Global Google infrastructure"
    sovereignty_notes = "Schrems II / US CLOUD Act / FISA 702 apply"
    # privacy 3.0: reCAPTCHA's function is device fingerprinting (timing,
    #   hardware, mouse/behaviour probes) scored at a self-interested US
    #   controller that reuses the signal — a behavioural profile under a
    #   foreign controller (rubric privacy 3.0). Not 4.0: not a declared
    #   cross-site ad-profile join. security 2.0: unpinned first-party
    #   loader, single-purpose hardened vendor (rubric 2.0). resilience
    #   2.5: bot protection is a supporting feature, replaceable with work
    #   (Turnstile/hCaptcha), US controller (rubric 2.5).
    impact_rating = ImpactRating(privacy=3.0, security=2.0, resilience=2.5)
    impact_notes = {
        "privacy": "Profiles the visitor through device-fingerprint and "
            "behaviour probes scored at a self-interested US controller.",
        "security": "An unpinned Google loader runs in your origin.",
        "resilience": "Bot protection on a US vendor — replaceable "
            "(Turnstile / hCaptcha) but with migration work.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _RECAPTCHA_ONLY_HOSTS:
            return True
        if host in _PATH_GATED_HOSTS:
            return urlparse(event.url).path.startswith(_RECAPTCHA_PATH_PREFIX)
        return False

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized reCAPTCHA parameter", IMPACT_LOW)
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
