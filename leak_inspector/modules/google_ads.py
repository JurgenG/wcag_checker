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

"""Google Ads / DoubleClick detector.

Recognizes Google's advertising-infrastructure cluster: conversion
tracking, view-through measurement, remarketing pixels, and ad-serving
infrastructure. GA4-flavored hits that *happen* to use DoubleClick
hostnames are claimed by the GA4 module instead.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_PII,
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
    ".doubleclick.net",
    ".googleadservices.com",
    ".googletagservices.com",
    ".googlesyndication.com",
    ".2mdn.net",
    ".ad-delivery.net",
    ".adtrafficquality.google",
)
_HOST_EXACT: frozenset[str] = frozenset({
    "doubleclick.net",
    "googleadservices.com",
    "googletagservices.com",
    "googlesyndication.com",
    "2mdn.net",
    "ad-delivery.net",
    "adtrafficquality.google",
    # DoubleClick Floodlight conversion tags are served from this Google
    # ad subdomain (``/ddm/fls/z/src=…`` paths). It is not under any of the
    # suffixes above, and ``google_misc`` only claims the bare google.com
    # apex — so without this exact entry the Floodlight beacons fall
    # through unclassified.
    "adservice.google.com",
})

_WWW_GOOGLE_RE = re.compile(r"^www\.google\.[a-z]{2,3}(?:\.[a-z]{2,3})?$")
_WWW_GOOGLE_ADS_PATH_PREFIXES: tuple[str, ...] = (
    "/pagead/",
    "/rmkt/",
    "/ccm/",
)


_PARAMS: dict[str, tuple[str, str, str]] = {
    "id":         (CAT_TECHNICAL,  "Conversion / Ads account ID (``AW-…`` or numeric)", IMPACT_LOW),
    "tid":        (CAT_TECHNICAL,  "Property / measurement ID echoed from GA4",  IMPACT_LOW),
    "label":      (CAT_TECHNICAL,  "Conversion label",                          IMPACT_LOW),
    "ai":         (CAT_TECHNICAL,  "Ad / creative ID",                          IMPACT_LOW),
    "correlator": (CAT_IDENTIFIER, "Per-impression correlation ID",             IMPACT_MEDIUM),
    "iu":         (CAT_CONTENT,    "DFP inventory unit",                        IMPACT_LOW),
    "auid":   (CAT_IDENTIFIER, "Persistent ads visitor pseudonym",              IMPACT_HIGH),
    # ``guid`` is handled value-aware in _classify (binary directive vs UUID).
    "uid":    (CAT_PII,        "Site-supplied user ID",                         IMPACT_HIGH),
    "ord":    (CAT_TECHNICAL,  "Cache-buster / unique order number",            IMPACT_LOW),
    "tt_authuser": (CAT_PII, "Signed-in Google account index (set when visitor is logged in)", IMPACT_MEDIUM),
    "is_vtc":   (CAT_BEHAVIORAL, "Is view-through conversion",                  IMPACT_MEDIUM),
    "value":    (CAT_BEHAVIORAL, "Conversion value (revenue)",                  IMPACT_MEDIUM),
    "currency_code": (CAT_BEHAVIORAL, "Conversion currency",                    IMPACT_LOW),
    "transaction_id": (CAT_BEHAVIORAL, "Transaction / order ID",                IMPACT_MEDIUM),
    "url":  (CAT_CONTENT, "Page URL the conversion / impression fired on",      IMPACT_MEDIUM),
    "ref":  (CAT_CONTENT, "Document referrer",                                  IMPACT_MEDIUM),
    "hn":   (CAT_CONTENT, "Host name of the calling page",                      IMPACT_LOW),
    "u_h":     (CAT_TECHNICAL, "Screen height",                                 IMPACT_LOW),
    "u_w":     (CAT_TECHNICAL, "Screen width",                                  IMPACT_LOW),
    "u_ah":    (CAT_TECHNICAL, "Available screen height (minus task bars)",     IMPACT_LOW),
    "u_aw":    (CAT_TECHNICAL, "Available screen width",                        IMPACT_LOW),
    "u_cd":    (CAT_TECHNICAL, "Color depth",                                   IMPACT_LOW),
    "u_his":   (CAT_TECHNICAL, "Browser history length (fingerprint surface)",  IMPACT_LOW),
    "u_tz":    (CAT_TECHNICAL, "Timezone offset (minutes from UTC)",            IMPACT_LOW),
    "u_java":  (CAT_TECHNICAL, "Java-enabled flag (legacy)",                    IMPACT_LOW),
    "u_nplug": (CAT_TECHNICAL, "Number of installed plugins (fingerprint surface)", IMPACT_LOW),
    "u_nmime": (CAT_TECHNICAL, "Number of registered MIME types (fingerprint surface)", IMPACT_LOW),
    "cv":     (CAT_TECHNICAL, "Conversion-pixel version",                       IMPACT_LOW),
    "fst":    (CAT_TECHNICAL, "First-session timestamp",                        IMPACT_LOW),
    "num":    (CAT_TECHNICAL, "Request number / counter",                       IMPACT_LOW),
    "bg":     (CAT_TECHNICAL, "Background indicator",                           IMPACT_LOW),
    "resp":   (CAT_TECHNICAL, "Expected response sentinel",                     IMPACT_LOW),
    "sendb":  (CAT_TECHNICAL, "Send-beacon flag",                               IMPACT_LOW),
    "ig":     (CAT_TECHNICAL, "Image-tag flag",                                 IMPACT_LOW),
    "frm":    (CAT_TECHNICAL, "Frame indicator (0 = top)",                      IMPACT_LOW),
    "async":  (CAT_TECHNICAL, "Async-load flag",                                IMPACT_LOW),
    "rfmt":   (CAT_TECHNICAL, "Response format",                                IMPACT_LOW),
    "fmt":    (CAT_TECHNICAL, "Request format",                                 IMPACT_LOW),
    "sz":     (CAT_TECHNICAL, "Ad slot size",                                   IMPACT_LOW),
    "sscte":  (CAT_TECHNICAL, "Server-side conversion tracking flag",           IMPACT_LOW),
    "random": (CAT_TECHNICAL, "Cache-buster",                                   IMPACT_LOW),
    "c":      (CAT_TECHNICAL, "Cache-buster / count",                           IMPACT_LOW),
    "gtm":    (CAT_TECHNICAL, "GTM container / workspace version string",       IMPACT_LOW),
    "output": (CAT_TECHNICAL, "Response output type",                           IMPACT_LOW),
    "ct_cookie_present": (CAT_CONSENT, "Conversion-tracking cookie-present flag", IMPACT_LOW),
    "aip":     (CAT_CONSENT, "Anonymize-IP flag",                               IMPACT_LOW),
    "dma":     (CAT_CONSENT, "EU Digital Markets Act consent signal",           IMPACT_LOW),
    "dma_cps": (CAT_CONSENT, "Consent provider state",                          IMPACT_LOW),
    "gcs":     (CAT_CONSENT, "Google consent state",                            IMPACT_LOW),
    "gcd":     (CAT_CONSENT, "Google consent defaults",                         IMPACT_LOW),
    "gcu":     (CAT_CONSENT, "Google consent-update event flag",                IMPACT_LOW),
    "npa":     (CAT_CONSENT, "Non-personalized ads flag",                       IMPACT_LOW),
    "pscdl":   (CAT_CONSENT, "Privacy Sandbox consent default",                 IMPACT_LOW),
    "en":       (CAT_BEHAVIORAL, "Event name (e.g. ``consent_update``)",        IMPACT_MEDIUM),
    "dl":       (CAT_CONTENT, "Document location (full page URL)",              IMPACT_MEDIUM),
    "dt":       (CAT_CONTENT, "Document title",                                 IMPACT_LOW),
    "tiba":     (CAT_CONTENT, "Tab / page title (alt form)",                    IMPACT_LOW),
    "scrsrc":   (CAT_CONTENT, "Script source that fired the beacon",            IMPACT_LOW),
    "rnd":      (CAT_TECHNICAL, "Random cache-buster",                          IMPACT_LOW),
    "navt":     (CAT_TECHNICAL, "Navigation type",                              IMPACT_LOW),
    "did":      (CAT_IDENTIFIER, "Data-signals identifier",                     IMPACT_LOW),
    "gdid":     (CAT_TECHNICAL, "Google data-signals identifier (per-property)", IMPACT_LOW),
    "_tu":      (CAT_TECHNICAL, "Encoded transport/tag bitfield",               IMPACT_LOW),
    "tag_exp":  (CAT_BEHAVIORAL, "Active experiments / A-B test bucket IDs",    IMPACT_MEDIUM),
    "tft":      (CAT_TECHNICAL, "Time first transmission timestamp",            IMPACT_LOW),
    "tfd":      (CAT_TECHNICAL, "Time first dispatch (ms since page-load)",     IMPACT_LOW),
    "ae":       (CAT_TECHNICAL, "Auto-event indicator",                         IMPACT_LOW),
    "rcb":      (CAT_TECHNICAL, "Retry / callback counter",                     IMPACT_LOW),
    "gcp":      (CAT_TECHNICAL, "Consent-payload index",                        IMPACT_LOW),
    "data":     (CAT_BEHAVIORAL, "Encoded ads-data-redaction payload",          IMPACT_MEDIUM),
    "apve":     (CAT_TECHNICAL, "Ads preview enabled flag",                     IMPACT_LOW),
    "apvf":     (CAT_TECHNICAL, "Ads preview format",                           IMPACT_LOW),
    "apvc":     (CAT_TECHNICAL, "Ads preview consent",                          IMPACT_LOW),
    "rmt_tld":  (CAT_TECHNICAL, "Remarketing TLD indicator",                    IMPACT_LOW),
    "ipr":      (CAT_CONSENT, "IP-redaction request flag",                      IMPACT_LOW),
    "cid":      (CAT_IDENTIFIER, "Opaque encoded correlation/cookie ID",        IMPACT_MEDIUM),
    "hl":       (CAT_TECHNICAL,  "Host language (UI / locale)",                 IMPACT_LOW),
    "dr":       (CAT_CONTENT,    "Document referrer",                           IMPACT_MEDIUM),
    "tids":     (CAT_TECHNICAL,  "Comma-separated list of GA / Ads tracking IDs", IMPACT_LOW),
    "slf_rd":   (CAT_TECHNICAL,  "Self-redirect counter (audience remarketing)", IMPACT_LOW),
}

_PARAM_PREFIXES: tuple[tuple[str, str, str, str], ...] = (
    ("ep.",  CAT_BEHAVIORAL, "Custom event parameter '{}' (forwarded from GA4)", IMPACT_MEDIUM),
    ("epn.", CAT_BEHAVIORAL, "Custom event parameter (numeric) '{}' (forwarded from GA4)", IMPACT_MEDIUM),
)


#: Values that mark ``guid`` as a binary directive rather than an identifier.
#: On Floodlight / conversion pings (``/ddm/fls/``, ``/pagead/…``) Google
#: sends the literal ``guid=ON`` to request a per-conversion GUID server-side
#: — a setting, not a visitor id. Only a non-flag value is an actual identifier.
_GUID_FLAG_VALUES: frozenset[str] = frozenset({
    "0", "1", "on", "off", "true", "false", "yes", "no",
})


def _classify(key: str, value: str = "") -> tuple[str, str, str]:
    if key == "guid":
        if value.strip().lower() in _GUID_FLAG_VALUES:
            return (
                CAT_TECHNICAL,
                "Conversion-tagging directive (binary flag, e.g. ``ON`` — not a visitor identifier)",
                IMPACT_LOW,
            )
        return (CAT_IDENTIFIER, "Global visitor UUID", IMPACT_HIGH)
    if key in _PARAMS:
        return _PARAMS[key]
    for prefix, cat, template, impact in _PARAM_PREFIXES:
        if key.startswith(prefix):
            return cat, template.format(key[len(prefix):]), impact
    return CAT_OTHER, "Unrecognized Google Ads parameter", IMPACT_LOW


@register
class GoogleAdsModule(TrackerModule):
    """Detect Google Ads / DoubleClick conversion, remarketing, and ad-serving traffic."""

    module_id = "google_ads"
    module_name = "Google Ads / DoubleClick"
    vendor = "Google LLC"
    legal_jurisdiction = "US"
    data_residency = "Google global CDN"
    sovereignty_notes = "Schrems II / US CLOUD Act / FISA 702 apply"
    # privacy 4.0: DoubleClick's purpose is joining this visit to a
    #   web-wide ad profile — third-party cookies, conversion/remarketing
    #   identifiers, cross-site by design (rubric privacy 4.0).
    # security 2.5: ordinary unpinned tag/pixel snippet. resilience 3.5:
    #   when Ads is the operator's outreach channel, the dependency is
    #   operational, not cosmetic (rubric 3.5).
    impact_rating = ImpactRating(privacy=4.0, security=2.5, resilience=3.5)
    impact_notes = {
        "privacy": "Joins this visit to Google's web-wide advertising "
            "profile — cross-site tracking is the product's purpose.",
        "security": "Loads an unpinned Google tag/pixel into your origin "
            "— remote code Google controls.",
        "resilience": "Outreach that runs on Google Ads becomes "
            "operationally dependent on a US ad platform you don't "
            "control.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _HOST_EXACT:
            return True
        if any(host.endswith(suffix) for suffix in _HOST_SUFFIXES):
            return True
        if _WWW_GOOGLE_RE.match(host):
            path = urlparse(event.url).path
            return any(path.startswith(prefix) for prefix in _WWW_GOOGLE_ADS_PATH_PREFIXES)
        return False

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _classify(key, value)
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
