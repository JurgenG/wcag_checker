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

"""Google Analytics detector (Universal Analytics + GA4 v2 + server-mediated v3).

Recognizes the full Google Analytics endpoint cluster — UA, GA4, and
server-mediated forms all ship to the same family of hosts and are
operated as a single product line:

* ``/g/collect`` (GA4 Measurement Protocol v2) and the legacy bare
  ``/collect`` on ``*.google-analytics.com``.
* ``/j/collect`` and ``/r/collect`` on ``*.google-analytics.com`` —
  Universal Analytics JSON and pixel collectors. UA properties were
  formally deprecated in 2023 but co-deployed UA+GA4 setups are
  extremely common in browsing captures of older sites.
* ``/analytics.js`` on ``*.google-analytics.com`` — the UA loader
  bundle. No telemetry on the URL itself but worth claiming so the
  asset shows up in the GA section of the report.
* ``/td`` and ``/gtag/js?is_td=1&…`` on ``*.googletagmanager.com`` —
  the newer "tag diagnostics" / server-mediated v3 transport. Same
  data as ``/g/collect`` (visitor pseudonym, page URL, experiment
  assignments); only the host and field names differ.

GA4 carries its parameters in both the URL query string and (for batched
payloads) the POST body — both are read via :attr:`RequestEvent.all_params`.

Parameter classifications below reflect Google's public Measurement
Protocol docs, the GTM/td endpoint conventions, and observed field
semantics. The list is the well-known core; unknown keys fall through
to ``CAT_OTHER`` so we still record them.
"""

from __future__ import annotations

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


# Hosts GA4 may post to. New regional endpoints (``region1.``...) are picked
# up by the suffix check in :meth:`GA4Module.matches`.
_GA4_HOST_SUFFIX = ".google-analytics.com"
_GA4_HOSTS_EXACT = {"google-analytics.com", "analytics.google.com"}

# Paths the GA endpoint cluster serves on ``*.google-analytics.com``.
# GA4 uses ``/g/collect``; UA uses ``/collect``, ``/j/collect`` (JSON
# POST), and ``/r/collect`` (pixel GET). ``/analytics.js`` is the UA
# loader script. The Urchin-era ``/ga.js`` + ``/urchin.js`` loaders and
# the ``/__utm.gif`` (and redirect-tagged ``/r/__utm.gif``) pixel
# transports cover legacy Universal Analytics deployments still active
# on older sites. We claim them all so the GA section is complete.
_GA_PATHS: frozenset[str] = frozenset({
    "/g/collect",
    "/collect",
    "/j/collect",
    "/r/collect",
    "/analytics.js",
    "/ga.js",
    "/urchin.js",
    "/__utm.gif",
    "/r/__utm.gif",
})

# Server-mediated GA4 ("tag diagnostics") rides on the GTM hostname.
_GTM_HOST_SUFFIX = ".googletagmanager.com"
_GTM_HOST_EXACT = "googletagmanager.com"

# Newer GA4 regional ingest hosts (``region1.analytics.google.com`` etc.).
# These are GA4 measurement, hyphenless host form, separate from the
# original ``*.google-analytics.com`` family.
_GA4_REGIONAL_SUFFIX = ".analytics.google.com"

# GA4 ad-attribution sidecar — fires alongside /g/collect with the same
# ``tid`` + ``cid`` payload to DoubleClick infrastructure.
_GA4_DOUBLECLICK_HOST = "stats.g.doubleclick.net"

# GA4 audience-remarketing pixel — fires to Google's country-localized
# search domain (``www.google.{tld}``) at the ``/ads/ga-audiences``
# path. Matched via :data:`_WWW_GOOGLE_RE` to avoid claiming unrelated
# ``google.com`` traffic.
_WWW_GOOGLE_RE = re.compile(r"^www\.google\.[a-z]{2,3}(?:\.[a-z]{2,3})?$")
_GA4_AUDIENCES_PATH = "/ads/ga-audiences"


# Parameter dictionary: key -> (category, human-readable meaning, privacy_impact).
_PARAMS: dict[str, tuple[str, str, str]] = {
    # --- protocol / dispatch ---
    "v":   (CAT_TECHNICAL,  "Measurement Protocol version (1 = UA, 2 = GA4 /g/collect, 3 = server-mediated /td)", IMPACT_LOW),
    "tid": (CAT_TECHNICAL,  "GA property ID — GA4 ``G-XXXXXX`` or UA ``UA-XXXXX-Y``", IMPACT_LOW),
    "id":  (CAT_TECHNICAL,  "GA4 measurement ID (G-XXXXXX) — /td-endpoint form", IMPACT_LOW),
    "pid": (CAT_TECHNICAL,  "GA4 numeric property ID",                          IMPACT_LOW),
    "tdp": (CAT_TECHNICAL,  "Tag-diagnostics property descriptor (property:account:event)", IMPACT_LOW),
    "t":   (CAT_BEHAVIORAL, "UA hit-type (``pageview``/``event``/…) or /td transport indicator", IMPACT_MEDIUM),
    "gtm": (CAT_TECHNICAL,  "GTM container / workspace version string",         IMPACT_LOW),
    "is_td": (CAT_TECHNICAL, "Server-mediated tag-diagnostics mode flag",       IMPACT_LOW),
    "cx":  (CAT_TECHNICAL,  "Loader context indicator (newer gtag.js)",         IMPACT_LOW),
    "_eu": (CAT_TECHNICAL,  "Encoded internal flags (opaque)",                  IMPACT_LOW),
    "_tu": (CAT_TECHNICAL,  "Encoded internal flags (opaque)",                  IMPACT_LOW),
    "tfd": (CAT_TECHNICAL,  "Time-first-dispatch (ms since page-load)",         IMPACT_LOW),
    "_r":  (CAT_TECHNICAL,  "Internal request-type flag (used by audience-remarketing pixel)", IMPACT_LOW),
    "slf_rd": (CAT_TECHNICAL, "Self-redirect counter (audience remarketing)",  IMPACT_LOW),
    "aip": (CAT_CONSENT,    "Anonymize-IP flag (1 = anonymize)",                IMPACT_LOW),
    # --- Universal Analytics (UA) specific fields ---
    "_v":   (CAT_TECHNICAL,  "Universal Analytics SDK version (e.g. ``j102``)", IMPACT_LOW),
    "_u":   (CAT_TECHNICAL,  "UA encoded capability bitfield (opaque)",         IMPACT_LOW),
    "_slc": (CAT_TECHNICAL,  "UA internal flag (opaque)",                       IMPACT_LOW),
    "_prs": (CAT_TECHNICAL,  "UA previous-referrer-state code (opaque)",        IMPACT_LOW),
    "lps":  (CAT_TECHNICAL,  "UA internal flag (opaque)",                       IMPACT_LOW),
    "_c":   (CAT_TECHNICAL,  "UA internal flag (opaque)",                       IMPACT_LOW),
    "_gid": (CAT_IDENTIFIER, "Universal Analytics ``_gid`` short-lived cookie",  IMPACT_MEDIUM),
    "_gl":  (CAT_IDENTIFIER, "Universal Analytics cross-domain linker token",    IMPACT_MEDIUM),
    "jid":  (CAT_IDENTIFIER, "UA per-hit identifier (used for hit deduplication)", IMPACT_LOW),
    "gjid": (CAT_IDENTIFIER, "UA per-hit identifier (used for hit deduplication)", IMPACT_LOW),
    "a":    (CAT_TECHNICAL,  "UA internal value (opaque numeric)",              IMPACT_LOW),
    "ec":   (CAT_BEHAVIORAL, "UA event category",                                IMPACT_MEDIUM),
    "ea":   (CAT_BEHAVIORAL, "UA event action",                                  IMPACT_MEDIUM),
    "el":   (CAT_BEHAVIORAL, "UA event label",                                   IMPACT_MEDIUM),
    "ev":   (CAT_BEHAVIORAL, "UA event value",                                   IMPACT_MEDIUM),
    "ni":   (CAT_BEHAVIORAL, "UA non-interaction flag",                          IMPACT_LOW),
    "ti":   (CAT_BEHAVIORAL, "UA transaction ID",                                IMPACT_MEDIUM),
    "tr":   (CAT_BEHAVIORAL, "UA transaction revenue",                           IMPACT_MEDIUM),
    "tt":   (CAT_BEHAVIORAL, "UA transaction tax",                               IMPACT_LOW),
    "ts":   (CAT_BEHAVIORAL, "UA transaction shipping",                          IMPACT_LOW),
    "in":   (CAT_BEHAVIORAL, "UA item name",                                     IMPACT_MEDIUM),
    "iv":   (CAT_BEHAVIORAL, "UA item variation",                                IMPACT_LOW),
    "ip":   (CAT_BEHAVIORAL, "UA item price",                                    IMPACT_MEDIUM),
    "iq":   (CAT_BEHAVIORAL, "UA item quantity",                                 IMPACT_LOW),
    "ic":   (CAT_BEHAVIORAL, "UA item code / SKU",                               IMPACT_MEDIUM),
    # --- Enhanced Conversions / Advanced Matching ---
    "em":      (CAT_PII,        "Hashed email (GA4 Enhanced Conversions / Advanced Matching)", IMPACT_HIGH),
    "ecid":    (CAT_IDENTIFIER, "Encrypted client ID (Enhanced Conversions)",    IMPACT_HIGH),
    "ec_mode": (CAT_TECHNICAL,  "Enhanced Conversions mode flag",                IMPACT_LOW),
    "ir":      (CAT_TECHNICAL,  "Internal-redirect / ignore-request flag",       IMPACT_LOW),
    "_gaz":    (CAT_IDENTIFIER, "GA cookie ``_gaz`` short-lived value",          IMPACT_MEDIUM),
    "gcu":     (CAT_CONSENT,    "Consent-update event flag",                     IMPACT_LOW),
    "gcut":    (CAT_CONSENT,    "Consent-update timestamp",                      IMPACT_LOW),
    "_p":  (CAT_TECHNICAL,  "Hit nonce — observed values are 13-digit epoch-ms timestamps",   IMPACT_LOW),
    "_s":  (CAT_TECHNICAL,  "Hit sequence number within the request",           IMPACT_LOW),
    "_z":  (CAT_TECHNICAL,  "Cache-buster",                                     IMPACT_LOW),
    "z":   (CAT_TECHNICAL,  "Cache-buster (/td endpoint)",                      IMPACT_LOW),
    "richsstsse": (CAT_TECHNICAL, "Server-sent events flag",                    IMPACT_LOW),
    # --- user / session identifiers ---
    "cid":  (CAT_IDENTIFIER, "Persistent client ID (the visitor pseudonym)",    IMPACT_HIGH),
    "pcid": (CAT_IDENTIFIER, "Persistent client ID — /td-endpoint form of cid", IMPACT_HIGH),
    "rtg":  (CAT_IDENTIFIER, "Route / random tag ID (often equals pcid)",       IMPACT_MEDIUM),
    "sid":  (CAT_IDENTIFIER, "Session ID",                                      IMPACT_MEDIUM),
    "uid":  (CAT_PII,        "Site-supplied user ID — often a real account id", IMPACT_HIGH),
    "_fid": (CAT_IDENTIFIER, "Firebase / app instance id",                      IMPACT_HIGH),
    "_uip": (CAT_PII,        "User IP override (server-side)",                  IMPACT_HIGH),
    # --- page / content ---
    "dl": (CAT_CONTENT, "Document location (full page URL)",                    IMPACT_MEDIUM),
    "dr": (CAT_CONTENT, "Document referrer",                                    IMPACT_MEDIUM),
    "dt": (CAT_CONTENT, "Document title",                                       IMPACT_LOW),
    "dh": (CAT_CONTENT, "Document hostname",                                    IMPACT_LOW),
    "dp": (CAT_CONTENT, "Document path",                                        IMPACT_LOW),
    # --- environment / fingerprint surface ---
    "ul":  (CAT_TECHNICAL, "User-agent language",                               IMPACT_LOW),
    "sr":  (CAT_TECHNICAL, "Screen resolution",                                 IMPACT_LOW),
    "sd":  (CAT_TECHNICAL, "Screen color depth",                                IMPACT_LOW),
    "vp":  (CAT_TECHNICAL, "Viewport size",                                     IMPACT_LOW),
    "ade": (CAT_TECHNICAL, "Ads data redaction flag",                           IMPACT_LOW),
    "frm": (CAT_TECHNICAL, "Frame indicator (0 = top frame)",                   IMPACT_LOW),
    # --- events ---
    "en":   (CAT_BEHAVIORAL, "Event name",                                      IMPACT_MEDIUM),
    "_et":  (CAT_BEHAVIORAL, "Engagement time in milliseconds",                 IMPACT_LOW),
    "seg":  (CAT_BEHAVIORAL, "Session engaged flag",                            IMPACT_LOW),
    "_ss":  (CAT_BEHAVIORAL, "Session start indicator",                         IMPACT_LOW),
    "_fv":  (CAT_BEHAVIORAL, "First-visit indicator",                           IMPACT_LOW),
    "_nsi": (CAT_BEHAVIORAL, "New session indicator",                           IMPACT_LOW),
    "sct":  (CAT_BEHAVIORAL, "Session count for this visitor",                  IMPACT_LOW),
    "exp":     (CAT_BEHAVIORAL, "Active experiments / A-B test assignments",    IMPACT_MEDIUM),
    "tag_exp": (CAT_BEHAVIORAL, "Active experiments / A-B test assignments (/g/collect form)", IMPACT_MEDIUM),
    "seq":  (CAT_TECHNICAL,  "Hit sequence number within batch (/td endpoint)", IMPACT_LOW),
    "slo":  (CAT_TECHNICAL,  "Sequence / scroll offset",                        IMPACT_LOW),
    "hlo":  (CAT_TECHNICAL,  "Hit load order",                                  IMPACT_LOW),
    "lst":  (CAT_TECHNICAL,  "Last sequence type",                              IMPACT_LOW),
    "bt":   (CAT_TECHNICAL,  "Beacon / batch type",                             IMPACT_LOW),
    "ct":   (CAT_TECHNICAL,  "Count or hit-type indicator",                     IMPACT_LOW),
    "mde":  (CAT_TECHNICAL,  "Measurement detail entries (feature flags per property)", IMPACT_LOW),
    "fin":  (CAT_TECHNICAL,  "Final batch flag",                                IMPACT_LOW),
    # --- campaign / acquisition ---
    "cs": (CAT_BEHAVIORAL, "Campaign source (utm_source equivalent)",           IMPACT_LOW),
    "cm": (CAT_BEHAVIORAL, "Campaign medium",                                   IMPACT_LOW),
    "cn": (CAT_BEHAVIORAL, "Campaign name",                                     IMPACT_LOW),
    "cc": (CAT_BEHAVIORAL, "Campaign content",                                  IMPACT_LOW),
    "ck": (CAT_BEHAVIORAL, "Campaign keyword",                                  IMPACT_LOW),
    # --- consent signals ---
    "gcs": (CAT_CONSENT, "Google consent state (ad/analytics granted/denied)",  IMPACT_LOW),
    "gcd": (CAT_CONSENT, "Google consent defaults",                             IMPACT_LOW),
    "dma": (CAT_CONSENT, "EU Digital Markets Act consent signal",               IMPACT_LOW),
    "dma_cps": (CAT_CONSENT, "Consent provider state",                          IMPACT_LOW),
    "npa": (CAT_CONSENT, "Non-personalized ads flag",                           IMPACT_LOW),
    "pscdl": (CAT_CONSENT, "Privacy Sandbox consent default",                   IMPACT_LOW),
    # --- legacy Urchin / Universal Analytics (``ga.js`` + ``__utm.gif``) ---
    # Older sites still ship hits through the Urchin parameter set. ``utmac``
    # carries the UA-XXXX property ID; ``utmcc`` carries the ``__utma`` cookie
    # value — that's the persistent visitor pseudonym, treated as HIGH.
    "utmac":    (CAT_TECHNICAL,  "Urchin UA property ID (e.g. ``UA-12345-1``)",  IMPACT_LOW),
    "utmcc":    (CAT_IDENTIFIER, "Urchin cookie payload — carries ``__utma`` visitor pseudonym", IMPACT_HIGH),
    "utmwv":    (CAT_TECHNICAL,  "Urchin tracker version (e.g. ``5.7.2``)",      IMPACT_LOW),
    "utmn":     (CAT_TECHNICAL,  "Urchin cache-buster nonce",                    IMPACT_LOW),
    "utms":     (CAT_TECHNICAL,  "Urchin session hit-sequence number",           IMPACT_LOW),
    "utmcs":    (CAT_TECHNICAL,  "Urchin page charset",                          IMPACT_LOW),
    "utmsr":    (CAT_TECHNICAL,  "Urchin screen resolution",                     IMPACT_LOW),
    "utmvp":    (CAT_TECHNICAL,  "Urchin viewport size",                         IMPACT_LOW),
    "utmsc":    (CAT_TECHNICAL,  "Urchin screen color depth",                    IMPACT_LOW),
    "utmul":    (CAT_TECHNICAL,  "Urchin user-language (e.g. ``nl-be``)",        IMPACT_LOW),
    "utmje":    (CAT_TECHNICAL,  "Urchin Java-enabled probe (fingerprint)",      IMPACT_LOW),
    "utmfl":    (CAT_TECHNICAL,  "Urchin Flash-version probe (fingerprint)",     IMPACT_LOW),
    "utmht":    (CAT_TECHNICAL,  "Urchin hit time (client epoch ms)",            IMPACT_LOW),
    "utmhid":   (CAT_TECHNICAL,  "Urchin random hit identifier",                 IMPACT_LOW),
    "utmjid":   (CAT_TECHNICAL,  "Urchin request identifier",                    IMPACT_LOW),
    "utmredir": (CAT_TECHNICAL,  "Urchin redirect flag (1 = pixel served via ``/r/``)", IMPACT_LOW),
    "utmu":     (CAT_TECHNICAL,  "Urchin encoded capability bitfield (opaque)",  IMPACT_LOW),
    "utmhn":    (CAT_CONTENT,    "Urchin host name (document host)",              IMPACT_LOW),
    "utmdt":    (CAT_CONTENT,    "Urchin document title",                         IMPACT_LOW),
    "utmp":     (CAT_CONTENT,    "Urchin page path",                              IMPACT_MEDIUM),
    "utmr":     (CAT_CONTENT,    "Urchin document referrer",                      IMPACT_MEDIUM),
    "utme":     (CAT_BEHAVIORAL, "Urchin event / custom-variable payload (e.g. ``5(role*staff)``)", IMPACT_MEDIUM),
    "utmt":     (CAT_BEHAVIORAL, "Urchin hit type (``event``/``transaction``/…)", IMPACT_MEDIUM),
    "utmni":    (CAT_BEHAVIORAL, "Urchin non-interaction flag",                   IMPACT_LOW),
}

# Prefix-keyed param families. Values are (category, meaning_template, impact)
# where ``{}`` in the template is filled with the sub-key after the prefix.
_PARAM_PREFIXES: tuple[tuple[str, str, str, str], ...] = (
    ("ep.", CAT_BEHAVIORAL, "Custom event parameter '{}'",   IMPACT_MEDIUM),
    ("epn.", CAT_BEHAVIORAL, "Custom event parameter (numeric) '{}'", IMPACT_MEDIUM),
    ("up.", CAT_PII,        "Custom user property '{}'",      IMPACT_HIGH),
    ("upn.", CAT_PII,       "Custom user property (numeric) '{}'", IMPACT_HIGH),
    ("pr",  CAT_BEHAVIORAL, "E-commerce product field '{}'",  IMPACT_LOW),
)


def _classify(key: str) -> tuple[str, str, str]:
    """Return (category, meaning, impact) for one Google Analytics parameter key."""
    if key in _PARAMS:
        return _PARAMS[key]
    for prefix, cat, template, impact in _PARAM_PREFIXES:
        if key.startswith(prefix):
            sub_key = key[len(prefix):]
            # Operators commonly mirror CMP consent state into user
            # properties (``up.cookie_consent=denied``). That value is
            # consent state, not personal data — don't let the PII
            # default for ``up.*`` / ``upn.*`` inflate it.
            if prefix in ("up.", "upn.") and "consent" in sub_key.lower():
                return (
                    CAT_CONSENT,
                    f"Custom user property '{sub_key}' (consent state)",
                    IMPACT_LOW,
                )
            return cat, template.format(sub_key), impact
    # Universal Analytics custom-dimension / custom-metric numeric slots:
    # ``cd1``, ``cd2``, …, ``cm1``, ``cm2``, …. Operators choose what
    # each slot tracks; common uses include logged-in role, plan tier,
    # page section — so flag as BEHAVIORAL MEDIUM by default.
    if len(key) > 2 and key[:2] in ("cd", "cm") and key[2:].isdigit():
        slot = key[2:]
        kind = "dimension" if key[:2] == "cd" else "metric"
        return (
            CAT_BEHAVIORAL,
            f"Universal Analytics custom {kind} #{slot}",
            IMPACT_MEDIUM,
        )
    return CAT_OTHER, "Unrecognized GA parameter", IMPACT_LOW


def _make_param(key: str, value: str, event_id: int, *, label: str | None = None) -> ParamInfo:
    """Build a ``ParamInfo`` for one GA4 key/value, classifying by ``key``.

    ``label`` overrides the displayed key (e.g. ``(body ev#3) en``) while
    classification still uses the underlying key (``en``) — that way
    body-event params still pick up the correct category / meaning from
    :data:`_PARAMS`.
    """
    category, meaning, impact = _classify(key)
    return ParamInfo(
        key=label if label is not None else key,
        value=value,
        category=category,
        meaning=meaning,
        privacy_impact=impact,
        event_index=event_id,
    )


@register
class GA4Module(TrackerModule):
    """Detect Google Analytics 4 hits via the Measurement Protocol v2."""

    module_id = "ga4"
    module_name = "Google Analytics 4"
    vendor = "Google LLC"
    legal_jurisdiction = "US"
    data_residency = "Google global CDN with regional ingest (e.g. region1.analytics.google.com routes EU traffic, but processing remains US-controlled)"
    sovereignty_notes = "Schrems II / US CLOUD Act / FISA 702 apply regardless of regional ingest endpoint"
    # privacy 3.0: durable client-id + full visit paths at a controller
    #   that reuses the data for its own ad/product purposes beyond the
    #   operator's instructions (rubric privacy 3.0). Plain tag only —
    #   the Consent-Mode-denied and FP-Mode-forwarded realities are
    #   Phase-5 variants / the FP-Mode module.
    # security 2.5: unpinned first-party gtag snippet, ordinary vendor
    #   (rubric 2.5). resilience 3.0: GA4 as the operator's measurement
    #   layer accumulates under US control (rubric 3.0).
    impact_rating = ImpactRating(privacy=3.0, security=2.5, resilience=3.0)
    impact_notes = {
        "privacy": "Google receives a durable visitor ID and full "
            "page-path history, and reuses it for its own ad/product "
            "purposes beyond this site.",
        "security": "The gtag.js snippet runs in your page's own origin "
            "with no integrity pin — Google can change what executes at "
            "any time.",
        "resilience": "Your analytics history and the decisions built on "
            "it accumulate inside a US-controlled platform — growing "
            "lock-in under foreign jurisdiction.",
    }

    #: Consent-Mode-denied variant: every collection beacon reports
    #: storage denied, so no durable client-id is persisted — milder
    #: privacy than free-running GA4. Snippet + measurement-layer
    #: dependency unchanged.
    _CONSENT_DENIED_RATING = ImpactRating(privacy=1.5, security=2.5, resilience=3.0)
    #: Evasion override: GA4 collection through a cloaked/proxied
    #: first-party host (the proposal's 9th worked example) — privacy can
    #: only rate *up*. Mirrors google_first_party_mode's base rating.
    _EVASION_RATING = ImpactRating(privacy=4.5, security=2.5, resilience=3.0)
    #: Param-key prefixes the analysis layer stamps on a cloaked/proxied
    #: hit (kept in sync with ``analysis.consent._OVERRIDE_PREFIXES``).
    _EVASION_PREFIXES = ("(cname-cloak)", "(fp-proxy)")
    #: Google Consent Mode value for "storage denied".
    _GCS_DENIED = "G100"

    #: Enhanced Conversions / Advanced Matching variant: a hashed login
    #: email (``em``) — or its ``ecid`` companion — ships an
    #: identified-person key to Google (rubric privacy 5.0: an
    #: advanced-matching pixel fed login email). Snippet + measurement
    #: layer unchanged, so only privacy moves.
    _EC_MATCH_RATING = ImpactRating(privacy=5.0, security=2.5, resilience=3.0)
    _EC_MATCH_KEYS = frozenset({"em", "ecid"})
    #: User-ID join variant: a site-supplied ``uid`` (real account id)
    #: stitches the GA4 pseudonym to a known account — profile joined to a
    #: platform identity (rubric privacy 3.5).
    _USER_ID_RATING = ImpactRating(privacy=3.5, security=2.5, resilience=3.0)
    _USER_ID_KEY = "uid"

    @staticmethod
    def _base_key(key: str) -> str:
        """Strip a ``parse()`` display label off a param key.

        Body params surface as ``(body) em`` / ``(body ev#2) em``; the
        underlying key is what follows the first ``") "``. Unlabeled keys
        pass through.
        """
        if key.startswith("(") and ") " in key:
            return key.split(") ", 1)[1]
        return key

    @staticmethod
    def _is_transmitted(key: str) -> bool:
        """True if ``key`` is one of GA4's *own* transmitted parameters.

        :meth:`parse` emits transmitted params either bare (query string)
        or under a ``(body…)`` label (batched POST). The analysis layer
        appends other params to the hit — ``(set-cookie) <name>``,
        ``(http) …``, ``(infra) …``, the ``(cname-cloak)`` / ``(fp-proxy)``
        evasion markers — whose names are arbitrary (site-chosen cookie
        names, connection metadata) and are *not* GA4 fields. They must
        not be mistaken for identity params like ``uid`` / ``em``.
        """
        return not key.startswith("(") or key.startswith("(body")

    def effective_rating(self, hits):
        """Select a per-capture variant from the hits, by severity.

        Descending precedence, first match wins:

        1. Enhanced Conversions matching (``em``/``ecid`` observed) — an
           identified-person key shipped, the gravest reality; dominates
           even a same-batch ``gcs=G100`` (if it's on the wire, it went).
        2. Evasion (cloak/proxy marker) — can only raise.
        3. User-ID join (``uid``) — pseudonym tied to a known account.
        4. Consent-Mode-denied — when *every* beacon reporting ``gcs``
           reports denied storage, no durable id persists (milder).

        With none of these observable, the base triple stands (certainty
        rule: unobservable settings don't exist for scoring).
        """
        base_keys = {
            self._base_key(p.key)
            for hit in hits for p in hit.params
            if self._is_transmitted(p.key)
        }
        if base_keys & self._EC_MATCH_KEYS:
            return self._EC_MATCH_RATING
        if any(
            p.key.startswith(self._EVASION_PREFIXES)
            for hit in hits for p in hit.params
        ):
            return self._EVASION_RATING
        if self._USER_ID_KEY in base_keys:
            return self._USER_ID_RATING
        gcs_values = [
            p.value for hit in hits for p in hit.params if p.key == "gcs"
        ]
        if gcs_values and all(v == self._GCS_DENIED for v in gcs_values):
            return self._CONSENT_DENIED_RATING
        return self.impact_rating

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        path = urlparse(event.url).path
        if host in _GA4_HOSTS_EXACT or host.endswith(_GA4_HOST_SUFFIX):
            return path in _GA_PATHS
        if host.endswith(_GA4_REGIONAL_SUFFIX):
            return path == "/g/collect" or path == "/collect"
        if host == _GTM_HOST_EXACT or host.endswith(_GTM_HOST_SUFFIX):
            if path == "/td":
                return True
            if path == "/gtag/js" and "is_td" in event.query_params:
                return True
        if host == _GA4_DOUBLECLICK_HOST and path == "/g/collect":
            return True
        if path == _GA4_AUDIENCES_PATH and _WWW_GOOGLE_RE.match(host):
            return True
        return False

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []

        # --- URL query params ----------------------------------------------
        query_keys: set[str] = set()
        for key, value in event.query_params.items():
            params.append(_make_param(key, value, event.event_id))
            query_keys.add(key)

        # --- Body params ---------------------------------------------------
        # GA4 batched POST mode ships one event per line in the body, each
        # line being urlencoded params (typically with ``Content-Type:
        # text/plain;charset=UTF-8`` from sendBeacon, which ``body_params``
        # alone would skip). Detect newline-delimited bodies and surface
        # each event's params under a ``(body ev#N)`` prefix so the report
        # shows what's actually in each batched event.
        body = (event.request_body or "").strip()
        if body:
            lines = [ln for ln in body.split("\n") if ln.strip()]
            if len(lines) > 1:
                for idx, line in enumerate(lines, start=1):
                    for key, value in parse_qsl(line.strip(), keep_blank_values=True):
                        params.append(_make_param(
                            key, value, event.event_id,
                            label=f"(body ev#{idx}) {key}",
                        ))
                params.append(ParamInfo(
                    key="(body) batched_event_count",
                    value=str(len(lines)),
                    category=CAT_BEHAVIORAL,
                    meaning="Number of events shipped in this batched POST",
                    privacy_impact=IMPACT_MEDIUM,
                    event_index=event.event_id,
                ))
            else:
                for key, value in parse_qsl(body, keep_blank_values=True):
                    if key in query_keys:
                        continue
                    params.append(_make_param(
                        key, value, event.event_id,
                        label=f"(body) {key}",
                    ))

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