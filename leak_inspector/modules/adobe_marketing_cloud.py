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

"""Adobe Experience Cloud (Marketing Cloud) detector.

Covers the four Adobe-controlled host families seen in browsing
captures of Adobe-instrumented sites:

* ``*.adobedtm.com`` — Adobe Launch / Dynamic Tag Manager.
* ``*.omtrdc.net`` — Adobe Analytics (formerly SiteCatalyst).
* ``*.demdex.net`` — Adobe Audience Manager (DMP). The ``/ibs:``
  endpoint encodes parameters in the URL **path**, not the query string.
* ``*.everesttech.net`` — Adobe Advertising Cloud.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlparse

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIXES: tuple[str, ...] = (
    ".adobedtm.com",
    ".demdex.net",
    ".omtrdc.net",
    ".everesttech.net",
)
_HOST_EXACT: frozenset[str] = frozenset({
    "adobedtm.com", "demdex.net", "omtrdc.net", "everesttech.net",
})


_PARAMS: dict[str, tuple[str, str, str]] = {
    "mid":     (CAT_IDENTIFIER, "Adobe Experience Cloud visitor pseudonym (38-digit numeric)", IMPACT_HIGH),
    "dpuuid":  (CAT_IDENTIFIER, "DMP user ID exchanged with the data provider — value format varies by partner", IMPACT_HIGH),
    "d_uuid":  (CAT_IDENTIFIER, "Adobe Advertising Cloud visitor ID",                          IMPACT_HIGH),
    "mcorgid": (CAT_TECHNICAL,  "Adobe Experience Cloud org ID (``<id>@AdobeOrg``)",           IMPACT_LOW),
    "d_orgid": (CAT_TECHNICAL,  "Adobe Experience Cloud org ID (``<id>@AdobeOrg``)",           IMPACT_LOW),
    "dpid":    (CAT_TECHNICAL,  "Data provider ID (per-partner DMP identifier)",               IMPACT_LOW),
    "advId":   (CAT_TECHNICAL,  "Adobe Advertising Cloud advertiser ID",                       IMPACT_LOW),
    "pxId":    (CAT_TECHNICAL,  "Adobe Advertising Cloud pixel / tag ID",                      IMPACT_LOW),
    "redir": (CAT_CONTENT, "Cookie-sync redirect URL — names the downstream partner receiving the Adobe visitor ID", IMPACT_HIGH),
    "px_evt":     (CAT_BEHAVIORAL, "Pixel event type code",                                    IMPACT_MEDIUM),
    "ev_transid": (CAT_BEHAVIORAL, "Transaction ID (when populated)",                          IMPACT_MEDIUM),
    "d_fieldgroup": (CAT_TECHNICAL, "Visitor ID Service field-group (``MC`` = Marketing Cloud, ``A`` = Analytics)", IMPACT_LOW),
    "d_visid_ver":  (CAT_TECHNICAL, "Visitor ID Service client version",                       IMPACT_LOW),
    "d_ver":        (CAT_TECHNICAL, "Visitor ID Service protocol version",                     IMPACT_LOW),
    "d_nsid":       (CAT_TECHNICAL, "Visitor ID Service namespace ID",                         IMPACT_LOW),
    "d_rtbd":       (CAT_TECHNICAL, "Visitor ID Service response-format request (``json``)",   IMPACT_LOW),
    "cachebuster": (CAT_TECHNICAL, "Random cache-buster",                                      IMPACT_LOW),
    "ts":          (CAT_TECHNICAL, "Request timestamp (epoch ms)",                             IMPACT_LOW),
    "gdpr":         (CAT_CONSENT, "IAB TCF: GDPR-applies flag",                                IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "IAB TCF consent string",                                    IMPACT_LOW),
    "google_cver":  (CAT_CONSENT, "Google consent / cookie-sync version",                      IMPACT_LOW),
}


def _parse_demdex_ibs_path(path: str) -> list[tuple[str, str]]:
    if not path.startswith("/ibs:"):
        return []
    encoded = path[len("/ibs:"):]
    return parse_qsl(encoded, keep_blank_values=True)


@register
class AdobeMarketingCloudModule(TrackerModule):
    """Detect Adobe Experience Cloud (Analytics + Audience Manager + Advertising Cloud + DTM)."""

    module_id = "adobe_marketing_cloud"
    module_name = "Adobe Experience Cloud"
    vendor = "Adobe Inc."
    legal_jurisdiction = "US"
    data_residency = "Adobe Experience Cloud (US / EU regions configurable per-customer; ingest hosts route accordingly)"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # privacy 4.0: AAM/demdex is an ID-sync hub joining the visit to a
    #   web-wide profile, cross-site by design. security 4.0: the demdex
    #   sync chain redirects into unenumerable fourth parties (rubric 4.0).
    # resilience 3.0: Adobe Experience Cloud is a deep US-controlled
    #   measurement + identity + tag-management dependency with heavy
    #   enterprise lock-in (rubric 3.0). The proposal's ID-sync-hub anchor.
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=3.0)
    impact_notes = {
        "privacy": "AAM/demdex is an ID-sync hub that joins this visit to "
            "a web-wide profile — cross-site by design.",
        "security": "The demdex sync chain redirects the visitor into "
            "fourth parties you cannot enumerate.",
        "resilience": "Adobe Experience Cloud is a deep US-controlled "
            "measurement + identity + tag-management dependency with heavy "
            "enterprise lock-in.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _HOST_EXACT:
            return True
        return any(host.endswith(suffix) for suffix in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        seen_keys: set[str] = set()

        path = urlparse(event.url).path
        for key, value in _parse_demdex_ibs_path(path):
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Adobe parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key, value=value, category=category,
                    meaning=meaning, privacy_impact=impact,
                    event_index=event.event_id,
                )
            )
            seen_keys.add(key)

        for key, value in event.all_params.items():
            if key in seen_keys:
                continue
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Adobe parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key, value=value, category=category,
                    meaning=meaning, privacy_impact=impact,
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
