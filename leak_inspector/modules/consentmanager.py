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

"""consentmanager Consent Management Platform detector.

consentmanager (consentmanager GmbH, Germany) is an IAB-TCF CMP seen in
the municipalities captures. It delivers its banner bundle from
``cdn.consentmanager.net`` (``/delivery/js/*.min.js``,
``/delivery/customdata/<base64>.js``) and serves the CMP itself plus its
own telemetry from ``delivery.consentmanager.net`` (``/delivery/cmp.php``,
``/delivery/info/``). The visited page URL rides in the ``h`` parameter
and the account ID in ``id``.

The consent decision itself is an IAB-TCF string this module does **not**
decode (TCF decoding is deferred — it lives in CMP-iframe storage we do
not yet snapshot; see TODO). So, like TrustArc / Sourcepoint, the banner
is *named* but the decision stays ``"unknown"``. The module ID is listed
in ``analysis.consent._CMP_MODULE_IDS`` so a consentmanager beacon firing
before the choice is not counted as a pre-consent tracking offender.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
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


#: Registrable domains consentmanager serves from (each incl. subdomains).
_DOMAINS: tuple[str, ...] = ("consentmanager.net", "consentmanager.de")


_PARAMS: dict[str, tuple[str, str, str]] = {
    "id":       (CAT_TECHNICAL, "consentmanager account / site ID",       IMPACT_LOW),
    "h":        (CAT_CONTENT,   "Page URL where the CMP loaded",          IMPACT_MEDIUM),
    "l":        (CAT_TECHNICAL, "Language code",                          IMPACT_LOW),
    "lp":       (CAT_TECHNICAL, "Page language code",                     IMPACT_LOW),
    "ls":       (CAT_TECHNICAL, "Language settings",                      IMPACT_LOW),
    "o":        (CAT_TECHNICAL, "Request timestamp / cache-buster",       IMPACT_LOW),
    "t":        (CAT_TECHNICAL, "CMP event type (e.g. pv = page view)",   IMPACT_LOW),
    "__cmpcc":  (CAT_CONSENT,   "Consent-cookie present flag (IAB TCF)",  IMPACT_LOW),
    "__cmpfcc": (CAT_CONSENT,   "Forced consent-cookie check flag (IAB TCF)", IMPACT_LOW),
}


@register
class ConsentManagerModule(TrackerModule):
    """Detect consentmanager CMP delivery / banner / telemetry requests."""

    module_id = "consentmanager"
    module_name = "consentmanager"
    vendor = "consentmanager GmbH"
    legal_jurisdiction = "DE"
    data_residency = "EU (Germany)"
    sovereignty_notes = ""
    # EU third-party CMP: privacy 1.5 / security 2.5 / resilience 1.0
    # (Germany, GDPR-native). See cookiebot for the shared shape.
    impact_rating = ImpactRating(privacy=1.5, security=2.5, resilience=1.0)
    impact_notes = {
        "privacy": "A consent record plus presence telemetry at a "
            "third-party CMP (EU, Germany).",
        "security": "Loads an unpinned CMP script into your origin.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return any(host == d or host.endswith("." + d) for d in _DOMAINS)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized consentmanager parameter", IMPACT_LOW)
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
