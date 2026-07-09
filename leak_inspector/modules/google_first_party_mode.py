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

"""Google Tag First-Party Mode (FP-Mode) detector.

Google rolled out "First-Party Mode" alongside Consent Mode v2 to keep
GA4 / GTM beacons surviving the browser-side restrictions on
third-party cookies and tracker blocklists. The operator deploys
Google's tagging-server image at a custom subdomain — typically
``g.<operator-tld>``, but any prefix works — and points gtag.js at
that subdomain. The browser sees first-party requests and first-party
cookies; the tagging server forwards every beacon to Google's
infrastructure server-side.

Browser-visible fingerprint (any one of these is sufficient on a
non-Google host):

* ``/g/collect`` with ``tid=G-XXXXXX`` — the GA4 collection endpoint
  cloned at the operator's subdomain.
* ``/gtag/js`` with ``id=G-XXXXXX`` — the gtag.js loader.
* ``/_/set_cookie`` — FP-Mode-specific cookie-setting endpoint that
  writes ``FPID`` / ``FPLC`` / ``FPGSID`` / ``FPAU`` on the operator's
  apex domain (``Max-Age`` up to 2 years, evading the 7-day cap browsers
  apply to third-party-set cookies).
* ``/_/service_worker/<n>/sw_iframe.html`` — FP-Mode service-worker
  iframe that proxies further beacons.

**Google Tag Gateway for advertisers** (May 2025) is the productized
successor: instead of a subdomain, the operator reserves a
*measurement path* on the main domain (e.g. ``/metrics``) and a CDN
rule (one-click on Cloudflare) routes it to Google's documented
origin ``<tag id>.fps.goog``. Google's setup guide shows the
measurement resources keeping their ``collect?v=2&tid=G-…`` shape
under the prefix; that the full ``/g/collect`` path segment survives
(``/metrics/g/collect``) is *inferred* from that, not verbatim-
documented. The path fingerprints above are therefore matched as
**suffixes** with the G-ID guard (worst case is a false negative),
and the certain anchors are the G-ID itself plus the ``*.fps.goog``
origin — any request reaching that domain directly (or via a CNAME
chain) is claimed as Google tag-serving infrastructure.

Canonical Google hosts (``*.google-analytics.com``,
``*.googletagmanager.com``, ``*.analytics.google.com``,
``stats.g.doubleclick.net``) are explicitly excluded so the existing
:mod:`leak_inspector.modules.ga4` and
:mod:`leak_inspector.modules.googletagmanager` modules keep ownership
of them.

Each claimed hit carries an HIGH-impact ``(fp-proxy)`` ParamInfo, the
analog of the ``(cname-cloak)`` finding emitted for DNS-level cloaks.
The proxy pattern is the reverse-proxy equivalent of a CNAME cloak
and warrants the same prominence in the report.

Parameter classification reuses :mod:`leak_inspector.modules.ga4`'s
dictionary — the request payload is identical to canonical GA4.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_HTTP_TRAFFIC,
    CAT_TECHNICAL,
    Hit,
    IMPACT_HIGH,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
    register,
)


#: GA4 property / measurement ID format. Universal Analytics ``UA-*`` is
#: intentionally excluded — FP-Mode is GA4-only by Google's own rollout.
_GA4_MEASUREMENT_ID_RE = re.compile(r"^G-[A-Z0-9]{6,}$")

#: FP-Mode infrastructure paths. These don't appear on canonical Google
#: hosts, so a match on these (regardless of host) is high-confidence
#: FP-Mode by itself — no extra query-param signature needed. Matched
#: as path *suffixes*: Google Tag Gateway (May 2025) nests the same
#: endpoints under an operator-chosen measurement path on the main
#: domain (e.g. ``/metrics/_/set_cookie``).
_FP_MODE_SET_COOKIE_SUFFIX = "/_/set_cookie"
_FP_MODE_SW_INFIX = "/_/service_worker/"
_FP_MODE_SW_SUFFIX = "/sw_iframe.html"

#: GA4 transport paths that ALSO appear on canonical Google hosts. We
#: require a G-* measurement ID to disambiguate from accidental
#: collisions on unrelated infrastructure. Matched as suffixes for the
#: same Tag Gateway reason (``/metrics/g/collect``).
_GA4_COLLECT_SUFFIX = "/g/collect"
_GA4_LOADER_SUFFIX = "/gtag/js"

#: Google's documented Tag Gateway / FP-Mode origin domain — routing
#: rules point ``<tag id>.fps.goog`` behind the operator's measurement
#: path, and subdomain deployments CNAME to it. Any request reaching
#: this domain directly is Google tag-serving infrastructure.
_FPS_GOOG_EXACT = "fps.goog"
_FPS_GOOG_SUFFIX = ".fps.goog"

#: Canonical Google hosts owned by :mod:`leak_inspector.modules.ga4` and
#: :mod:`leak_inspector.modules.googletagmanager`. Excluded here so this
#: module never shadows them, even if import order were ever rearranged.
_CANONICAL_GOOGLE_HOST_SUFFIXES: tuple[str, ...] = (
    ".google-analytics.com",
    ".googletagmanager.com",
    ".analytics.google.com",
)
_CANONICAL_GOOGLE_HOST_EXACT: frozenset[str] = frozenset({
    "google-analytics.com",
    "analytics.google.com",
    "googletagmanager.com",
    "stats.g.doubleclick.net",
})


def _is_canonical_google_host(host: str) -> bool:
    """Return ``True`` for hosts claimed by the canonical GA4 / GTM modules."""
    host = host.lower()
    if host in _CANONICAL_GOOGLE_HOST_EXACT:
        return True
    return any(host.endswith(suffix) for suffix in _CANONICAL_GOOGLE_HOST_SUFFIXES)


def _ga4_measurement_id_from(event: RequestEvent) -> str | None:
    """Return the GA4 ``G-*`` ID from ``tid`` or ``id``, or ``None``."""
    tid_or_id = event.query_params.get("tid") or event.query_params.get("id") or ""
    return tid_or_id if _GA4_MEASUREMENT_ID_RE.match(tid_or_id) else None


@register
class GoogleFirstPartyModeModule(TrackerModule):
    """Detect Google Tag First-Party Mode (operator-proxied GA4 / GTM)."""

    module_id = "google_first_party_mode"
    module_name = "Google Tag (First-Party Mode proxy)"
    vendor = "Google LLC"
    #: Opt out of the generic ``Google LLC`` bucket: FP-Mode is a
    #: deliberate operator install (custom subdomain + tagging-server
    #: deployment) that warrants visibility separate from a passive
    #: GA4 tag. Vendor of record is unchanged — sovereignty /
    #: jurisdiction analysis still groups under Google LLC.
    rollup_label = "Google LLC (Tag First-Party Mode proxy)"
    legal_jurisdiction = "US"
    data_residency = (
        "Operator-controlled tagging server in front of Google's analytics "
        "infrastructure; beacons forwarded server-side (region varies)"
    )
    sovereignty_notes = (
        "Operator-owned reverse proxy that forwards beacons server-side to "
        "Google. The first-party-looking host evades third-party-cookie "
        "restrictions and tracker blocklists, but the controller of record "
        "remains Google LLC — Schrems II / US CLOUD Act / FISA 702 apply."
    )
    # privacy 4.5: this is GA4 wrapped in a consent-evading technique
    #   (first-party proxy disguising a third-party transfer) — the rubric
    #   privacy 4.5 "deliberate evasion" line, which overrides the 3.0 the
    #   underlying GA4 payload would earn. This realizes the proposal's
    #   ninth worked example (GA4 behind FP-Mode) as a module base rating,
    #   not a Phase-5 variant. security 2.5 / resilience 3.0: the forwarded
    #   beacon is still GA4's gtag snippet and measurement layer.
    impact_rating = ImpactRating(privacy=4.5, security=2.5, resilience=3.0)
    impact_notes = {
        "privacy": "GA4 disguised as first-party: the proxy makes a "
            "third-party transfer to Google look local, defeating "
            "tracker blockers and consent expectations.",
        "security": "Routes an unpinned Google tag through an "
            "operator-run proxy into your origin.",
        "resilience": "The same US-controlled measurement dependency as "
            "GA4, with extra infrastructure to keep it alive.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if _is_canonical_google_host(host):
            return False
        if host == _FPS_GOOG_EXACT or host.endswith(_FPS_GOOG_SUFFIX):
            return True
        path = urlparse(event.url).path
        if path.endswith(_FP_MODE_SET_COOKIE_SUFFIX):
            return True
        if _FP_MODE_SW_INFIX in path and path.endswith(_FP_MODE_SW_SUFFIX):
            return True
        if path.endswith(_GA4_COLLECT_SUFFIX) or path.endswith(_GA4_LOADER_SUFFIX):
            return _ga4_measurement_id_from(event) is not None
        return False

    def parse(self, event: RequestEvent) -> Hit:
        # Lazy import: keeps the module graph acyclic and reuses GA4's
        # well-tested parameter dictionary.
        from .ga4 import _classify

        params: list[ParamInfo] = []

        # The defining finding for this module — mirrors how the CNAME-cloak
        # detector marks first-party-looking hits with a HIGH-impact flag.
        params.append(ParamInfo(
            key="(fp-proxy) host",
            value=event.host,
            category=CAT_HTTP_TRAFFIC,
            meaning=(
                "Google Analytics traffic served via an operator-owned "
                "subdomain instead of *.google-analytics.com / "
                "*.googletagmanager.com. The browser sees first-party "
                "requests and cookies (immune to third-party-cookie "
                "restrictions and tracker blocklists), but beacons are "
                "forwarded server-side to Google. Controller of record "
                "remains Google LLC."
            ),
            privacy_impact=IMPACT_HIGH,
            event_index=event.event_id,
        ))

        measurement_id = _ga4_measurement_id_from(event)
        if measurement_id is not None:
            params.append(ParamInfo(
                key="(fp-proxy) measurement_id",
                value=measurement_id,
                category=CAT_TECHNICAL,
                meaning="GA4 property ID being forwarded via the first-party proxy",
                privacy_impact=IMPACT_LOW,
                event_index=event.event_id,
            ))

        # URL query params — classify via GA4's dictionary.
        seen_query_keys: set[str] = set()
        for key, value in event.query_params.items():
            category, meaning, impact = _classify(key)
            params.append(ParamInfo(
                key=key, value=value, category=category, meaning=meaning,
                privacy_impact=impact, event_index=event.event_id,
            ))
            seen_query_keys.add(key)

        # Body params (rare in this capture, but FP-Mode does POST batched
        # events the same way canonical GA4 does — keep the dictionary
        # classification working for them too).
        body = (event.request_body or "").strip()
        if body:
            for key, value in parse_qsl(body, keep_blank_values=True):
                if key in seen_query_keys:
                    continue
                category, meaning, impact = _classify(key)
                params.append(ParamInfo(
                    key=f"(body) {key}", value=value, category=category,
                    meaning=meaning, privacy_impact=impact,
                    event_index=event.event_id,
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