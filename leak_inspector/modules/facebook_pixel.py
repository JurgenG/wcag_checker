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

"""Meta (Facebook) Pixel detector.

Recognizes ``/tr`` and ``/tr/`` on ``*.facebook.com`` (the Pixel
measurement endpoint), ``/b.php`` (cookie-sync hop for the persistent
``_fbp`` cookie), and ``connect.facebook.net`` (the JS loader).
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlparse

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


_FB_HOST_SUFFIX = ".facebook.com"
_FB_HOST_EXACT = "facebook.com"
_FB_LOADER_HOST = "connect.facebook.net"

# Meta CDN serving JS/CSS/image assets for the Page Plugin iframe.
# ``static.xx.fbcdn.net`` ships ``/rsrc.php/...`` bundles; ``scontent*`` hosts
# (sometimes geo-tagged like ``scontent-cdg6-1.xx.fbcdn.net``) serve the
# embedded page images.
_FBCDN_SUFFIX = ".fbcdn.net"

# Versioned social-plugin path: ``/v<major>.<minor>/plugins/<name>.php``.
# The page plugin (page.php) is the most common; like.php, share_button.php,
# follow.php, etc. follow the same shape.
_PLUGIN_VERSIONED_RE = re.compile(r"^/v\d+\.\d+/plugins/[a-z_]+\.php$", re.IGNORECASE)
# Older / unversioned form: ``/plugins/<name>.php``.
_PLUGIN_UNVERSIONED_RE = re.compile(r"^/plugins/[a-z_]+\.php$", re.IGNORECASE)
# Telemetry subpaths for the social plugins (page logging, tab renderer, …).
_PLATFORM_PLUGIN_PREFIX = "/platform/plugin/"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "id":          (CAT_TECHNICAL,  "Pixel ID (the advertiser's tracking key)", IMPACT_LOW),
    "fbp":         (CAT_IDENTIFIER, "Persistent browser visitor ID (the ``_fbp`` cookie)", IMPACT_HIGH),
    "fbc":         (CAT_IDENTIFIER, "Click identifier from ``fbclid`` (the ``_fbc`` cookie)", IMPACT_HIGH),
    "external_id": (CAT_PII,        "Site-supplied external user ID (often a real account id)", IMPACT_HIGH),
    "eid":         (CAT_TECHNICAL,  "Event ID for server-side de-duplication",  IMPACT_LOW),
    "p":           (CAT_TECHNICAL,  "Pixel ID being synced into (b.php endpoint)", IMPACT_LOW),
    "e":           (CAT_IDENTIFIER, "External visitor pseudonym from the partner — the ID being linked into Meta's _fbp graph", IMPACT_HIGH),
    "t":           (CAT_TECHNICAL,  "Cookie TTL in seconds (e.g. ``2592000`` = 30 days)", IMPACT_LOW),
    "ev": (CAT_BEHAVIORAL, "Event name (PageView, Purchase, Lead, ViewContent, …)", IMPACT_MEDIUM),
    "ec": (CAT_TECHNICAL,  "Pixel error count",                                IMPACT_LOW),
    "dl": (CAT_CONTENT, "Document location (full page URL)",                   IMPACT_MEDIUM),
    "rl": (CAT_CONTENT, "Document referrer URL",                               IMPACT_MEDIUM),
    "if": (CAT_TECHNICAL, "Iframe indicator",                                  IMPACT_LOW),
    "ts": (CAT_TECHNICAL, "Client-side timestamp",                             IMPACT_LOW),
    "it": (CAT_TECHNICAL, "Initial timestamp",                                 IMPACT_LOW),
    "_t": (CAT_TECHNICAL, "Send timestamp",                                    IMPACT_LOW),
    "sw": (CAT_TECHNICAL, "Screen width",                                      IMPACT_LOW),
    "sh": (CAT_TECHNICAL, "Screen height",                                     IMPACT_LOW),
    "v":  (CAT_TECHNICAL, "Pixel library version",                             IMPACT_LOW),
    "r":  (CAT_TECHNICAL, "Pixel release tag",                                 IMPACT_LOW),
    "a":  (CAT_TECHNICAL, "Loader/agent identifier (e.g. tmgoogletagmanager)", IMPACT_LOW),
    "noscript": (CAT_TECHNICAL, "Image-pixel fallback indicator",              IMPACT_LOW),
    "coo": (CAT_TECHNICAL, "First-party cookie context flag",                  IMPACT_LOW),
    "em":      (CAT_PII, "Advanced Matching: hashed email address",             IMPACT_HIGH),
    "ph":      (CAT_PII, "Advanced Matching: hashed phone number",              IMPACT_HIGH),
    "fn":      (CAT_PII, "Advanced Matching: hashed first name",                IMPACT_HIGH),
    "ln":      (CAT_PII, "Advanced Matching: hashed last name",                 IMPACT_HIGH),
    "db":      (CAT_PII, "Advanced Matching: hashed date of birth",             IMPACT_HIGH),
    "ge":      (CAT_PII, "Advanced Matching: hashed gender",                    IMPACT_HIGH),
    "ct":      (CAT_PII, "Advanced Matching: hashed city",                      IMPACT_HIGH),
    "st":      (CAT_PII, "Advanced Matching: hashed state/region",              IMPACT_HIGH),
    "zp":      (CAT_PII, "Advanced Matching: hashed postal code",               IMPACT_HIGH),
    "country": (CAT_PII, "Advanced Matching: hashed country",                   IMPACT_HIGH),
    "gdpr":            (CAT_CONSENT, "GDPR-applies flag",                       IMPACT_LOW),
    "gdpr_consent":    (CAT_CONSENT, "TCF consent string",                      IMPACT_LOW),
    "us_privacy":      (CAT_CONSENT, "US privacy (IAB CCPA) signal",            IMPACT_LOW),
    "dpo_ccpa":        (CAT_CONSENT, "CCPA opt-out flag",                       IMPACT_LOW),
    "dpo":             (CAT_CONSENT, "Data Processing Options (``LDU`` = Limited Data Use)", IMPACT_LOW),
    "dpoco":           (CAT_CONSENT, "Limited Data Use country code (0 = auto-detect)",      IMPACT_LOW),
    "dpost":           (CAT_CONSENT, "Limited Data Use state code (0 = auto-detect)",        IMPACT_LOW),
    "domain":   (CAT_CONTENT,    "Embedding-page domain (echoed in body)",       IMPACT_MEDIUM),
    "hme":      (CAT_IDENTIFIER, "Advanced Matching state token (hex-encoded value, exact role not documented)", IMPACT_MEDIUM),
    "tz":       (CAT_TECHNICAL,  "Visitor timezone offset (fingerprint surface)", IMPACT_LOW),
    "rqm":      (CAT_TECHNICAL,  "Request method / mode indicator",              IMPACT_LOW),
    "redirect": (CAT_TECHNICAL,  "Redirect-mode flag (``1`` = redirect after pixel fires)", IMPACT_LOW),
    # --- social plugin (Page Plugin / Like / Share / etc.) params ---
    "app_id":     (CAT_TECHNICAL,  "Facebook App ID the embed is associated with", IMPACT_LOW),
    "href":       (CAT_CONTENT,    "FB resource being embedded (Page, post, video URL)", IMPACT_MEDIUM),
    "channel":    (CAT_CONTENT,    "XD-arbiter callback URL — reveals embedding origin", IMPACT_MEDIUM),
    "config_json": (CAT_CONTENT,   "Plugin configuration JSON (often includes ``href``/``app_id``)", IMPACT_MEDIUM),
    "adapt_container_width": (CAT_TECHNICAL, "Page Plugin layout flag",          IMPACT_LOW),
    "show_facepile":         (CAT_TECHNICAL, "Page Plugin facepile flag",        IMPACT_LOW),
    "small_header":          (CAT_TECHNICAL, "Page Plugin header-size flag",     IMPACT_LOW),
    "hide_cover":            (CAT_TECHNICAL, "Page Plugin cover-image flag",     IMPACT_LOW),
    "tabs":                  (CAT_TECHNICAL, "Page Plugin enabled tabs (timeline/events/messages)", IMPACT_LOW),
    "locale":                (CAT_TECHNICAL, "Plugin locale (e.g. ``fr_FR``)",   IMPACT_LOW),
    "width":                 (CAT_TECHNICAL, "Plugin width",                     IMPACT_LOW),
    "height":                (CAT_TECHNICAL, "Plugin height",                    IMPACT_LOW),
    "key":                   (CAT_TECHNICAL, "Plugin variant key (``timeline``/``events``/…)", IMPACT_LOW),
}

_SKIP_KEYS: frozenset[str] = frozenset({
    "cs_est",
    "ler",
    "tm",
})

_SKIP_KEY_PREFIXES: tuple[str, ...] = ("pmd[", "expv2[")

_PARAM_PREFIXES: tuple[tuple[str, str, str, str], ...] = (
    ("cd[", CAT_BEHAVIORAL, "Custom event data field '{}'",  IMPACT_MEDIUM),
    ("ud[", CAT_PII,        "User-data field '{}' (hashed PII)", IMPACT_HIGH),
)


def _classify(key: str) -> tuple[str, str, str]:
    if key in _PARAMS:
        return _PARAMS[key]
    for prefix, cat, template, impact in _PARAM_PREFIXES:
        if key.startswith(prefix) and key.endswith("]"):
            inner = key[len(prefix):-1]
            return cat, template.format(inner), impact
    return CAT_OTHER, "Unrecognized Meta Pixel parameter", IMPACT_LOW


def _should_skip(key: str) -> bool:
    if key in _SKIP_KEYS:
        return True
    return any(key.startswith(p) for p in _SKIP_KEY_PREFIXES)


_CAPI_EVENT_FIELDS: tuple[tuple[str, str, str, str, str], ...] = (
    ("event_name",       "(body) event_name",       CAT_BEHAVIORAL,
     "Event name (PageView / Purchase / Lead / ViewContent / …)",     IMPACT_MEDIUM),
    ("event_id",         "(body) event_id",         CAT_IDENTIFIER,
     "Event ID used for server-side de-duplication",                  IMPACT_LOW),
    ("event_time",       "(body) event_time",       CAT_TECHNICAL,
     "Event timestamp (epoch seconds)",                               IMPACT_LOW),
    ("event_source_url", "(body) event_source_url", CAT_CONTENT,
     "Source URL of the event (page that fired it)",                  IMPACT_MEDIUM),
    ("action_source",    "(body) action_source",    CAT_TECHNICAL,
     "Action source (website / email / system_generated / app / …)",  IMPACT_LOW),
    ("opt_out",          "(body) opt_out",          CAT_CONSENT,
     "Opt-out flag",                                                  IMPACT_LOW),
)


def _parse_body(
    body: str | None,
    body_params_already_classified: bool,
) -> list[ParamInfo]:
    if not body:
        return []
    body = body.strip()
    if not body:
        return []

    if body[:1] == "{":
        try:
            decoded = json.loads(body)
        except (ValueError, TypeError):
            decoded = None
        if isinstance(decoded, dict):
            capi = _parse_capi_json(decoded)
            if capi:
                return capi

    if body_params_already_classified:
        return []
    return _parse_form_encoded_fallback(body)


def _parse_form_encoded_fallback(body: str) -> list[ParamInfo]:
    if body.lstrip().startswith("------") or "\nContent-Disposition: form-data" in body:
        return [ParamInfo(
            key="(body) multipart_event_data",
            value=f"{len(body)} bytes (multipart/form-data, not parsed)",
            category=CAT_BEHAVIORAL,
            meaning=(
                "Body is multipart/form-data — likely a custom-integration POST "
                "carrying serialized DOM fragments, file uploads, or other complex "
                "event data. v1.0 does not unpack multipart bodies."
            ),
            privacy_impact=IMPACT_MEDIUM,
            event_index=0,
        )]
    out: list[ParamInfo] = []
    pairs = parse_qsl(body, keep_blank_values=True)
    if not pairs:
        return []
    for key, value in pairs:
        category, meaning, impact = _classify(key)
        out.append(ParamInfo(
            key=f"(body) {key}",
            value=value,
            category=category,
            meaning=meaning,
            privacy_impact=impact,
            event_index=0,
        ))
    return out


def _parse_capi_json(decoded: dict) -> list[ParamInfo]:
    data = decoded.get("data")
    if not isinstance(data, list) or not data:
        return []

    out: list[ParamInfo] = [
        ParamInfo(
            key="(body) capi_event_count",
            value=str(len(data)),
            category=CAT_BEHAVIORAL,
            meaning="Number of events shipped in this Conversions-API-for-Web POST",
            privacy_impact=IMPACT_MEDIUM,
            event_index=0,
        ),
    ]
    event_names_seen = sorted({
        str(ev.get("event_name", "")) for ev in data
        if isinstance(ev, dict) and ev.get("event_name")
    })
    if event_names_seen:
        out.append(ParamInfo(
            key="(body) event_names",
            value=", ".join(event_names_seen),
            category=CAT_BEHAVIORAL,
            meaning="Distinct event names in this batch",
            privacy_impact=IMPACT_MEDIUM,
            event_index=0,
        ))

    first = data[0] if isinstance(data[0], dict) else None
    if first is None:
        return out

    for json_key, label, category, meaning, impact in _CAPI_EVENT_FIELDS:
        value = first.get(json_key)
        if value:
            out.append(ParamInfo(
                key=label,
                value=str(value)[:120],
                category=category,
                meaning=meaning,
                privacy_impact=impact,
                event_index=0,
            ))

    user_data = first.get("user_data")
    if isinstance(user_data, dict):
        for ud_key, ud_value in sorted(user_data.items()):
            if ud_value is None or ud_value == "":
                continue
            descriptor = _USER_DATA_DESCRIPTORS.get(ud_key, ud_key)
            out.append(ParamInfo(
                key=f"(body) user_data.{ud_key}",
                value=str(ud_value)[:80],
                category=CAT_PII,
                meaning=f"Advanced Matching: {descriptor}",
                privacy_impact=IMPACT_HIGH,
                event_index=0,
            ))

    custom_data = first.get("custom_data")
    if isinstance(custom_data, dict):
        for cd_key, cd_value in sorted(custom_data.items()):
            if cd_value is None or cd_value == "":
                continue
            if cd_key == "search_string":
                category, impact = CAT_PII, IMPACT_HIGH
                meaning = "Custom data: visitor search query (free text)"
            else:
                category, impact = CAT_BEHAVIORAL, IMPACT_MEDIUM
                meaning = f"Custom data: {cd_key}"
            out.append(ParamInfo(
                key=f"(body) custom_data.{cd_key}",
                value=str(cd_value)[:120],
                category=category,
                meaning=meaning,
                privacy_impact=impact,
                event_index=0,
            ))

    return out


_USER_DATA_DESCRIPTORS: dict[str, str] = {
    "em":         "hashed email",
    "ph":         "hashed phone",
    "fn":         "hashed first name",
    "ln":         "hashed last name",
    "db":         "hashed date of birth",
    "ge":         "hashed gender",
    "ct":         "hashed city",
    "st":         "hashed state / region",
    "zp":         "hashed postal code",
    "country":    "hashed country",
    "external_id": "site-supplied external user ID",
    "client_ip_address": "visitor IP",
    "client_user_agent": "visitor User-Agent",
    "fbc":        "click identifier (``_fbc`` cookie)",
    "fbp":        "browser ID (``_fbp`` cookie)",
    "subscription_id": "subscription ID",
    "lead_id":    "lead ID",
}


@register
class FacebookPixelModule(TrackerModule):
    """Detect Meta Pixel measurement and loader requests."""

    module_id = "facebook_pixel"
    module_name = "Meta (Facebook) Pixel"
    vendor = "Meta Platforms, Inc."
    legal_jurisdiction = "US"
    data_residency = "Meta global infrastructure"
    sovereignty_notes = "Schrems II / US CLOUD Act / FISA 702 apply"
    # privacy 4.0: the Pixel's purpose is joining this visit to Meta's
    #   web-wide profile — persistent _fbp, cookie-sync /b.php, advanced
    #   matching (rubric privacy 4.0, cross-site by design). Advanced-
    #   matching with hashed email shipped is the 5.0 case → a Phase-5
    #   variant keyed on observable matching params, not the base.
    # security 2.5: ordinary unpinned pixel/loader snippet. resilience
    #   3.5: operational dependence on Meta's ad ecosystem — custom
    #   audiences, conversion optimisation (rubric 3.5).
    impact_rating = ImpactRating(privacy=4.0, security=2.5, resilience=3.5)
    impact_notes = {
        "privacy": "Joins this visit to Meta's web-wide profile via the "
            "persistent _fbp cookie and cookie-sync — cross-site tracking "
            "is the product's purpose.",
        "security": "Loads an unpinned Meta pixel/loader into your origin.",
        "resilience": "Custom audiences and conversion optimisation make "
            "the operator operationally dependent on Meta's ad ecosystem.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host == _FB_LOADER_HOST:
            return True
        if host.endswith(_FBCDN_SUFFIX):
            # Meta CDN assets pulled by the social-plugin iframe.
            return True
        if host == _FB_HOST_EXACT or host.endswith(_FB_HOST_SUFFIX):
            path = urlparse(event.url).path
            if path == "/tr" or path == "/tr/":
                return True
            if path == "/b.php" or path.endswith("/b.php"):
                return True
            # Social plugins (Page Plugin, Like, Share, …) live at
            # ``/v<n>.<m>/plugins/<name>.php`` or the older ``/plugins/<name>.php``.
            if _PLUGIN_VERSIONED_RE.match(path) or _PLUGIN_UNVERSIONED_RE.match(path):
                return True
            # ``/platform/plugin/...`` telemetry (page-logging, tab-renderer, …).
            if path.startswith(_PLATFORM_PLUGIN_PREFIX):
                return True
        return False

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            if _should_skip(key):
                continue
            category, meaning, impact = _classify(key)
            params.append(
                ParamInfo(
                    key=key, value=value, category=category, meaning=meaning,
                    privacy_impact=impact, event_index=event.event_id,
                )
            )
        body_params_already_seen = bool(event.body_params)
        for body_param in _parse_body(event.request_body, body_params_already_seen):
            body_param.event_index = event.event_id
            params.append(body_param)
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
