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

"""hCaptcha detector.

Independent CAPTCHA / bot-challenge service, same product class as
Google reCAPTCHA and Cloudflare Turnstile. The hCaptcha JS bundle
collects device-fingerprint signals (timing, hardware, browser
quirks, mouse-movement) and produces a token the embedding site
verifies server-side.

All hCaptcha traffic flows through ``hcaptcha.com`` and its CDN
``newassets.hcaptcha.com``:

* ``hcaptcha.com/1/api.js`` — primary loader.
* ``hcaptcha.com/captcha/v1/...`` — RPC + iframe surface.
* ``newassets.hcaptcha.com/...`` — image / asset CDN.

The actual fingerprint signals travel in POST bodies and challenge
tokens — invisible to v1.0 capture. What we can surface from query
strings is the per-customer ``sitekey`` and the widget configuration.
"""

from __future__ import annotations

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


_HOST_SUFFIX = ".hcaptcha.com"
_HOST_EXACT = "hcaptcha.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "sitekey": (CAT_TECHNICAL,  "hCaptcha public site key (per-customer)",      IMPACT_LOW),
    "id":      (CAT_IDENTIFIER, "Widget instance ID",                           IMPACT_LOW),
    "rqdata":  (CAT_IDENTIFIER, "Encrypted challenge request data",             IMPACT_MEDIUM),
    "theme":           (CAT_TECHNICAL, "Widget theme (light / dark)",           IMPACT_LOW),
    "size":            (CAT_TECHNICAL, "Widget size (normal / compact / invisible)", IMPACT_LOW),
    "hl":              (CAT_TECHNICAL, "Widget language",                       IMPACT_LOW),
    "tabindex":        (CAT_TECHNICAL, "Widget tab-index",                      IMPACT_LOW),
    "callback":              (CAT_TECHNICAL, "Success-callback name",          IMPACT_LOW),
    "expired-callback":      (CAT_TECHNICAL, "Token-expired callback name",    IMPACT_LOW),
    "chalexpired-callback":  (CAT_TECHNICAL, "Challenge-expired callback name", IMPACT_LOW),
    "error-callback":        (CAT_TECHNICAL, "Error callback name",            IMPACT_LOW),
    "close-callback":        (CAT_TECHNICAL, "Close callback name",            IMPACT_LOW),
    "open-callback":         (CAT_TECHNICAL, "Open callback name",             IMPACT_LOW),
    "endpoint":  (CAT_TECHNICAL, "hCaptcha API endpoint override",              IMPACT_LOW),
    "assethost": (CAT_TECHNICAL, "Asset-host override",                         IMPACT_LOW),
    "imghost":   (CAT_TECHNICAL, "Image-host override",                         IMPACT_LOW),
    "reportapi": (CAT_TECHNICAL, "Report-API endpoint",                         IMPACT_LOW),
    "sentry":    (CAT_TECHNICAL, "hCaptcha-internal Sentry-reporting flag",     IMPACT_LOW),
    "host":      (CAT_TECHNICAL, "Host context override",                       IMPACT_LOW),
    "recaptchacompat": (CAT_TECHNICAL, "reCAPTCHA-compatibility shim flag",     IMPACT_LOW),
    "custom":    (CAT_TECHNICAL, "Custom-widget flag",                          IMPACT_LOW),
    "render":    (CAT_TECHNICAL, "Render mode (explicit / auto)",               IMPACT_LOW),
    "v":   (CAT_TECHNICAL, "hCaptcha protocol version",                         IMPACT_LOW),
    "onload":   (CAT_TECHNICAL, "Onload-callback name",                         IMPACT_LOW),
}


@register
class HcaptchaModule(TrackerModule):
    """Detect hCaptcha loader, iframe, RPC, and asset traffic."""

    module_id = "hcaptcha"
    module_name = "hCaptcha"
    vendor = "Intuition Machines, Inc."
    legal_jurisdiction = "US"
    data_residency = "Global"
    sovereignty_notes = "Marketed as a privacy-respecting alternative to reCAPTCHA; US CLOUD Act still applies"
    # Bot challenge: privacy 2.0 (device-challenge telemetry, contained,
    #   less aggressive than reCAPTCHA's 3.0; rubric 2.0). security 1.5
    #   (sandboxed cross-origin iframe). resilience 2.5 (US, replaceable
    #   supporting feature — rubric 2.5).
    impact_rating = ImpactRating(privacy=2.0, security=1.5, resilience=2.5)
    impact_notes = {
        "privacy": "A bot challenge that collects device-challenge "
            "telemetry — contained, less aggressive than reCAPTCHA.",
        "security": "Runs in a sandboxed cross-origin iframe — compromise "
            "stays in the frame.",
        "resilience": "A US vendor for a replaceable supporting feature.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized hCaptcha parameter", IMPACT_LOW)
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
