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

"""Cookie Script Consent Management Platform detector.

A smaller CMP, encountered in your captures. The browser SDK loads
from ``cdn.cookie-script.com`` (per-site script bundle) and ships
consent state to ``consent.cookie-script.com``.

The per-site script URL has the form
``cdn.cookie-script.com/s/<client-id>.js``; the per-site identifier
rides in the path rather than the query string, so the report's
representative-hit URL is where you'll see it.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIX = ".cookie-script.com"
_HOST_EXACT = "cookie-script.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "lang":        (CAT_TECHNICAL, "Banner language",                           IMPACT_LOW),
    "language":    (CAT_TECHNICAL, "Banner language (alt form)",                IMPACT_LOW),
    "v":           (CAT_TECHNICAL, "Banner SDK version",                        IMPACT_LOW),
    # --- consent-event payload fields ---
    "action":      (CAT_BEHAVIORAL, "Consent action taken (accept / deny / customize)", IMPACT_MEDIUM),
    "category":    (CAT_CONSENT,    "Consent category accepted",                IMPACT_LOW),
    "consenttext": (CAT_CONSENT,    "Consent text shown to the visitor",        IMPACT_LOW),
    "dnt":         (CAT_CONSENT,    "Do-Not-Track header value as observed",    IMPACT_LOW),
    "page":        (CAT_CONTENT,    "Page URL where consent was recorded",      IMPACT_MEDIUM),
    "time":        (CAT_TECHNICAL,  "Consent-event timestamp",                  IMPACT_LOW),
    "script":      (CAT_TECHNICAL,  "Cookie-Script script ID / version",        IMPACT_LOW),
}


@register
class CookieScriptModule(TrackerModule):
    """Detect Cookie Script CMP loader, configuration, and consent requests."""

    module_id = "cookie_script"
    module_name = "Cookie Script"
    vendor = "Cookie-Script.com"
    legal_jurisdiction = "LT"
    data_residency = "EU (Lithuania)"
    sovereignty_notes = ""
    # EU third-party CMP: privacy 1.5 / security 2.5 / resilience 1.0
    # (Lithuania, GDPR-native). See cookiebot for the shared shape.
    impact_rating = ImpactRating(privacy=1.5, security=2.5, resilience=1.0)
    impact_notes = {
        "privacy": "A consent record plus presence telemetry at a "
            "third-party CMP (EU, Lithuania).",
        "security": "Loads an unpinned CMP script into your origin.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Cookie Script parameter", IMPACT_LOW)
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
