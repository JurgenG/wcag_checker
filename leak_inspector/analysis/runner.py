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

"""Analysis runner.

Iterates a bundle's event stream, dispatches each :class:`RequestEvent`
to the matching tracker module via the registry, and collects every
produced :class:`Hit` into an :class:`Analysis` result.

The dedup rule lives here, not in the modules: a "representative hit"
collapses entries sharing
``(module_id, endpoint, param-key-set, event-type)``. A new endpoint,
a new parameter key, a new event type, or a new module triggers a
fresh representative.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlparse

import tldextract

from ..bundle import BundleReadError, BundleReader
from ..bundle.manifest import Manifest
from ..dns_posture import DNSPosture
from ..dns_posture.types import IPInfo
from ..events import Event, NavigationEvent, RequestEvent, StorageSnapshotEvent
from ..modules import detect
from ..modules.matomo import is_hosted_matomo_host, is_mtm_container_path
from ..modules.plausible import is_hosted_plausible_host
from ..modules.snowplow import is_hosted_snowplow_host
from .banner_markup import detect_self_hosted_banners
from .consent import ConsentState, derive_consent_state
from .cookie_classifier import classify_cookie_tracker
from .sri import detect_missing_sri, detect_protected_sri
from .operator_families import same_operator
from ..modules.base import (
    CAT_HTTP_TRAFFIC,
    Hit,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    MODULE_KIND_TRACKER,
    ParamInfo,
    TrackerModule,
    all_modules,
)


# v1.0 modules only consume RequestEvents, so the event-type slot in the
# dedup key is always this literal. Future modules consuming other event
# types will widen this naturally.
_REQUEST_EVENT_TYPE = "request"


#: Per-analysis cap on distinct ``host_enricher`` invocations.
#:
#: Each invocation runs A/AAAA DNS lookups plus a Team Cymru WHOIS
#: query. A hostile bundle that fabricates thousands of distinct
#: hostnames matching the self-hosted-collector detectors (Matomo /
#: Plausible / Snowplow) would fan out N DNS + N WHOIS queries per
#: analysis, usable for resolver-side reconnaissance or as a
#: reflection amplifier through the analyst's resolver.
#:
#: A small cap (50) is enough for any realistic capture — a single
#: site rarely contacts more than a handful of self-hosted collector
#: hosts — while defeating the amplification. When the cap is hit,
#: the runner surfaces an ``(infra) enrichment_capped`` ParamInfo on
#: the first dropped hit so the truncation is visible in the report.
ENRICH_HOST_CAP = 50


# --- ambient HTTP-traffic params -------------------------------------------
#
# Every external request discloses ambient metadata to the vendor by virtue
# of being made — visitor IP via the TCP connection, plus a fixed set of
# request headers. None of this is parameter-payload data; it's transport
# overhead. The runner attaches one ParamInfo per disclosed bit to every
# hit so reporters can surface them as a first-class category alongside
# the URL/body params each module parses out.

# Keys are lowercase header names; values describe how we classify each.
# Headers not in this map are treated as zero-signal protocol overhead
# (Accept, Accept-Encoding, Sec-Fetch-*, Host, Connection, …) and skipped.
_HEADER_CLASSIFICATION: dict[str, tuple[str, str]] = {
    "referer":              ("Page URL that triggered this request — reveals visitor's browsing context", IMPACT_HIGH),
    "cookie":               ("Cookies attached to this request (third-party tracking IDs if vendor has set any)", IMPACT_HIGH),
    "user-agent":           ("Browser / OS / version fingerprint",                   IMPACT_MEDIUM),
    "sec-ch-ua":            ("Client Hints — full browser brand list",               IMPACT_MEDIUM),
    "sec-ch-ua-platform":   ("Client Hints — operating system",                      IMPACT_MEDIUM),
    "sec-ch-ua-platform-version": ("Client Hints — operating-system version",        IMPACT_MEDIUM),
    "sec-ch-ua-arch":       ("Client Hints — CPU architecture",                      IMPACT_MEDIUM),
    "sec-ch-ua-model":      ("Client Hints — device model",                          IMPACT_MEDIUM),
    "sec-ch-ua-full-version-list": ("Client Hints — full browser version list",     IMPACT_MEDIUM),
    "sec-ch-ua-mobile":     ("Client Hints — mobile flag",                           IMPACT_LOW),
    "accept-language":      ("Visitor's language preferences",                       IMPACT_LOW),
    "origin":               ("Originating page's scheme + host (set on CORS / POST)", IMPACT_LOW),
    "dnt":                  ("Do-Not-Track signal (informational)",                  IMPACT_LOW),
    "sec-gpc":              ("Global Privacy Control signal (informational)",        IMPACT_LOW),
    "x-forwarded-for":      ("Visitor IP relayed by a proxy",                        IMPACT_HIGH),
}


def _ambient_traffic_params(event: RequestEvent) -> list[ParamInfo]:
    """Return ``http_traffic`` ParamInfos describing what *every* request leaks.

    Two sources are surfaced:

    * **Visitor IP** — always disclosed via the TCP connection, even
      though the captured event doesn't carry the value (BiDi does not
      expose the client's source address). We emit a synthetic entry so
      readers see that IP exposure happened, with the value placeholder
      ``"(disclosed via TCP connection)"``.
    * **Headers** — the subset in :data:`_HEADER_CLASSIFICATION` (Referer,
      Cookie, User-Agent, Client Hints, Accept-Language, Origin, DNT,
      Sec-GPC, X-Forwarded-For). Anything else (Accept, Accept-Encoding,
      Sec-Fetch-*, Host, Connection, …) is protocol overhead with no
      privacy signal beyond what the request itself already discloses
      and is skipped.

    Header lookup is case-insensitive — BiDi sometimes returns ``Referer``
    and sometimes ``referer`` depending on the request.
    """
    params: list[ParamInfo] = [
        ParamInfo(
            key="(http) ip",
            value="(disclosed via TCP connection)",
            category=CAT_HTTP_TRAFFIC,
            meaning="Visitor IP address — always disclosed by virtue of the connection itself",
            privacy_impact=IMPACT_HIGH,
            event_index=event.event_id,
        )
    ]
    seen: set[str] = set()
    for raw_key, raw_value in event.headers.items():
        lower = raw_key.lower()
        if lower in seen:
            continue
        seen.add(lower)
        classification = _HEADER_CLASSIFICATION.get(lower)
        if classification is None:
            continue
        meaning, impact = classification
        # For Cookie we show presence + length only — the value itself is
        # the tracking ID we don't want to splash across reports.
        if lower == "cookie":
            display_value = f"(present, {len(raw_value)} chars)"
        else:
            display_value = raw_value
        params.append(
            ParamInfo(
                key=f"(http) {lower}",
                value=display_value,
                category=CAT_HTTP_TRAFFIC,
                meaning=meaning,
                privacy_impact=impact,
                event_index=event.event_id,
            )
        )
    return params


# --- Set-Cookie attribute analysis -----------------------------------------
#
# Each captured response may carry one or more ``Set-Cookie`` headers
# describing cookies the vendor is asking the browser to persist.
# The attributes on those headers carry distinct privacy signals:
#
#   * ``SameSite=None`` + ``Secure`` is the modern cross-site tracking
#     prerequisite — the cookie is sent on cross-site requests.
#   * Long ``Expires`` / ``Max-Age`` lifetimes turn a single hit into
#     a multi-month or multi-year tracking handle.
#   * ``Partitioned`` (CHIPS) opts the cookie into per-top-level-site
#     partitioning, which neutralises cross-site tracking even when
#     ``SameSite=None`` is set.
#   * ``HttpOnly`` absent means the cookie value is JS-accessible — any
#     other script on the page can read it and exfiltrate it.
#
# We surface one ``ParamInfo`` row per cookie with the cookie value
# redacted (only its byte length is shown — the value is the tracking
# ID itself). Privacy impact is derived from the attribute combination.
#
# Limit: a Set-Cookie header on a response does not guarantee the
# browser actually stored the cookie. Modern browsers reject e.g.
# ``SameSite=None`` without ``Secure``, or CHIPS-bound cookies sent to
# unpartitioned top-level contexts. We surface what the server tried
# to set; we don't model the browser's acceptance policy.

#: Days after which a cookie counts as "persistent" (raises impact).
_PERSISTENT_DAYS_THRESHOLD = 30


def _parse_lifetime(
    max_age: str | None, expires: str | None, reference: datetime | None
) -> tuple[str, float | None]:
    """Return (human-readable lifetime, lifetime in days) for a cookie.

    ``Max-Age`` wins over ``Expires`` per RFC 6265. Returns ``("session",
    None)`` if neither attribute is present.
    """
    def _format(seconds: float) -> str:
        """Compact human-readable duration (``~1.2y`` / ``~14d`` / ``~3h`` / ``~25m`` / ``Ns``)."""
        days = seconds / 86400.0
        if days >= 365:
            return f"~{days/365:.1f}y"
        if days >= 1:
            return f"~{days:.0f}d"
        if seconds >= 3600:
            return f"~{seconds/3600:.0f}h"
        if seconds >= 60:
            return f"~{seconds/60:.0f}m"
        return f"{int(seconds)}s"

    if max_age is not None:
        try:
            seconds = int(max_age)
        except ValueError:
            return f"Max-Age={max_age}", None
        if seconds <= 0:
            return "deleted (Max-Age<=0)", 0.0
        return _format(seconds), seconds / 86400.0
    if expires is not None and reference is not None:
        try:
            exp_dt = parsedate_to_datetime(expires)
        except (TypeError, ValueError):
            return f"Expires={expires[:30]}", None
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        delta_seconds = (exp_dt - reference).total_seconds()
        if delta_seconds <= 0:
            return "deleted (past Expires)", 0.0
        return _format(delta_seconds), delta_seconds / 86400.0
    return "session", None


def _classify_cookie(
    same_site: str | None, lifetime_days: float | None, partitioned: bool
) -> str:
    """Derive a privacy impact from the cookie's tracking-relevant attributes.

    Rules:

    * ``Partitioned`` (CHIPS) overrides everything else → LOW. The cookie
      is keyed to the top-level site and cannot follow the visitor
      across origins.
    * Otherwise base impact comes from ``SameSite``:

      - ``None`` (cross-site-capable): HIGH if persistent (>30d), else
        MEDIUM.
      - ``Lax`` or unset (most browsers default to Lax-ish): MEDIUM if
        persistent, else LOW.
      - ``Strict``: LOW.
    """
    if partitioned:
        return IMPACT_LOW
    persistent = lifetime_days is not None and lifetime_days > _PERSISTENT_DAYS_THRESHOLD
    s = (same_site or "").lower()
    if s == "none":
        return IMPACT_HIGH if persistent else IMPACT_MEDIUM
    if s == "strict":
        return IMPACT_LOW
    # ``Lax`` or unset
    return IMPACT_MEDIUM if persistent else IMPACT_LOW


def _parse_set_cookie_line(line: str) -> tuple[str, int, dict[str, str], set[str]]:
    """Parse one ``Set-Cookie`` header line.

    Returns ``(name, value_length, attrs_with_values, attr_flags)``. The
    cookie value itself is discarded — only its byte length is reported.
    """
    head, _, rest = line.partition(";")
    name, _, value = head.partition("=")
    name = name.strip()
    value_length = len(value)
    attrs: dict[str, str] = {}
    flags: set[str] = set()
    if rest:
        for raw in rest.split(";"):
            piece = raw.strip()
            if not piece:
                continue
            if "=" in piece:
                k, _, v = piece.partition("=")
                attrs[k.strip().lower()] = v.strip()
            else:
                flags.add(piece.lower())
    return name, value_length, attrs, flags


def _extract_set_cookie_entries(
    event: RequestEvent,
    *,
    is_first_party: bool,
    vendor: str,
) -> list:
    """Parse every ``Set-Cookie`` header on a response into structured entries.

    Returns a list of :class:`leak_inspector.report.document.CookieEntry`
    objects — one per cookie set on the response. Used both by
    :func:`_set_cookie_params` (which converts each entry to a
    ParamInfo for the per-hit table) and by :func:`analyze_events`
    (which accumulates them onto :attr:`Analysis.cookies` for the
    report-wide cookie overview section).

    ``is_first_party`` and ``vendor`` are caller-supplied because the
    Analysis is the layer that knows the first-party domain set and the
    matched module's vendor label.
    """
    # Lazy import — document.py imports nothing from analysis, so the
    # reverse direction is also safe but only as a deferred reference.
    from ..report.document import CookieEntry

    response_headers = event.response_headers or {}
    raw: str | None = None
    for key, value in response_headers.items():
        if key.lower() == "set-cookie":
            raw = value
            break
    if not raw:
        return []

    reference: datetime | None = None
    try:
        reference = datetime.fromisoformat(
            event.timestamp.replace("Z", "+00:00")
        )
    except (AttributeError, ValueError):
        reference = None
    if reference is not None and reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)

    entries: list = []
    for cookie_line in raw.split("\n"):
        cookie_line = cookie_line.strip()
        if not cookie_line:
            continue
        name, _value_length, attrs, flags = _parse_set_cookie_line(cookie_line)
        if not name:
            continue
        same_site = (attrs.get("samesite") or "").lower()
        max_age_attr = attrs.get("max-age")
        expires_attr = attrs.get("expires")
        domain = attrs.get("domain") or ""
        path = attrs.get("path") or "/"
        secure = "secure" in flags
        http_only = "httponly" in flags
        partitioned = "partitioned" in flags

        lifetime_label, lifetime_days = _parse_lifetime(
            max_age_attr, expires_attr, reference
        )
        max_age_seconds: int | None = None
        if max_age_attr is not None:
            try:
                max_age_seconds = int(max_age_attr)
            except ValueError:
                max_age_seconds = None
        impact = _classify_cookie(same_site, lifetime_days, partitioned)

        entries.append(CookieEntry(
            name=name,
            host=event.host,
            vendor=vendor,
            is_first_party=is_first_party,
            domain=domain,
            path=path,
            max_age_seconds=max_age_seconds,
            lifetime_days=lifetime_days,
            lifetime_human=lifetime_label,
            same_site=same_site,
            secure=secure,
            http_only=http_only,
            partitioned=partitioned,
            privacy_impact=impact,
        ))
    return entries


def _jar_cookie_to_entry(
    raw: dict,
    *,
    host: str,
    is_first_party: bool,
    ref_epoch: float | None,
    source: str = "stored",
):
    """Build a :class:`CookieEntry` from one browser-jar cookie record.

    The record is a ``driver.get_cookies()`` entry (``{name, domain,
    path, secure, httpOnly, sameSite, expiry, ...}``) captured into a
    storage snapshot. The cookie **value** is deliberately ignored — it
    is the identifier we must not store. ``ref_epoch`` is the snapshot's
    capture time (Unix seconds) used to turn the absolute ``expiry`` into
    a lifetime; a missing ``expiry`` means a session cookie. Returns
    ``None`` for a nameless record.
    """
    from ..report.document import CookieEntry

    name = raw.get("name")
    if not name:
        return None
    same_site = (raw.get("sameSite") or "").lower()
    secure = bool(raw.get("secure"))
    http_only = bool(raw.get("httpOnly"))
    domain = raw.get("domain") or ""
    path = raw.get("path") or "/"

    lifetime_human, lifetime_days = "session", None
    max_age_seconds: int | None = None
    expiry = raw.get("expiry")
    if expiry is not None and ref_epoch is not None:
        try:
            seconds = int(float(expiry) - ref_epoch)
        except (TypeError, ValueError):
            seconds = None
        if seconds is not None:
            lifetime_human, lifetime_days = _parse_lifetime(str(seconds), None, None)
            max_age_seconds = seconds

    impact = _classify_cookie(same_site, lifetime_days, False)
    # Recognised tracker cookie? Label it with the vendor and carry the
    # module_id so scoring can link it to a forwarding/cloaking hit.
    tracker = classify_cookie_tracker(name)
    vendor = tracker[1] if tracker else host
    tracker_module_id = tracker[0] if tracker else ""
    return CookieEntry(
        name=name,
        host=host,
        vendor=vendor,
        is_first_party=is_first_party,
        domain=domain,
        path=path,
        max_age_seconds=max_age_seconds,
        lifetime_days=lifetime_days,
        lifetime_human=lifetime_human,
        same_site=same_site,
        secure=secure,
        http_only=http_only,
        partitioned=False,
        privacy_impact=impact,
        source=source,
        tracker_module_id=tracker_module_id,
    )


def _set_cookie_params(event: RequestEvent) -> list[ParamInfo]:
    """Parse every ``Set-Cookie`` header on the response into ParamInfos.

    Thin wrapper around :func:`_extract_set_cookie_entries` that converts
    each structured entry into the per-hit ParamInfo format the report
    has always used for cookies. The structured entries themselves are
    accumulated onto :attr:`Analysis.cookies` by :func:`analyze_events`.
    """
    response_headers = event.response_headers or {}
    raw: str | None = None
    for key, value in response_headers.items():
        if key.lower() == "set-cookie":
            raw = value
            break
    if not raw:
        return []

    # We need the value byte length per cookie for the displayed
    # summary — re-walk the raw header for that one piece since the
    # structured entry intentionally redacts it.
    reference: datetime | None = None
    try:
        reference = datetime.fromisoformat(
            event.timestamp.replace("Z", "+00:00")
        )
    except (AttributeError, ValueError):
        reference = None
    if reference is not None and reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)

    params: list[ParamInfo] = []
    for cookie_line in raw.split("\n"):
        cookie_line = cookie_line.strip()
        if not cookie_line:
            continue
        name, value_length, attrs, flags = _parse_set_cookie_line(cookie_line)
        if not name:
            continue
        same_site = attrs.get("samesite")
        max_age = attrs.get("max-age")
        expires = attrs.get("expires")
        domain = attrs.get("domain")
        path = attrs.get("path")
        secure = "secure" in flags
        http_only = "httponly" in flags
        partitioned = "partitioned" in flags

        lifetime_label, lifetime_days = _parse_lifetime(max_age, expires, reference)
        impact = _classify_cookie(same_site, lifetime_days, partitioned)

        summary_bits: list[str] = [f"value:{value_length}B"]
        summary_bits.append(f"lifetime={lifetime_label}")
        summary_bits.append(f"SameSite={same_site or '(unset)'}")
        if domain:
            summary_bits.append(f"Domain={domain}")
        if path and path != "/":
            summary_bits.append(f"Path={path}")
        if secure:
            summary_bits.append("Secure")
        summary_bits.append("HttpOnly" if http_only else "HttpOnly:absent (JS-readable)")
        if partitioned:
            summary_bits.append("Partitioned (CHIPS)")

        if partitioned:
            meaning = "Cookie set by tracker; ``Partitioned`` (CHIPS) prevents cross-site reuse"
        elif (same_site or "").lower() == "none":
            if lifetime_days is not None and lifetime_days > _PERSISTENT_DAYS_THRESHOLD:
                meaning = "Persistent third-party tracking cookie — sent on cross-site requests, lifetime longer than 30 days"
            else:
                meaning = "Cross-site-capable cookie (``SameSite=None``) but short-lived"
        elif (same_site or "").lower() == "strict":
            meaning = "Strict-only cookie — not sent on cross-site requests"
        else:
            if lifetime_days is not None and lifetime_days > _PERSISTENT_DAYS_THRESHOLD:
                meaning = "Persistent cookie (``SameSite=Lax`` / unset) — sent on top-level navigations"
            else:
                meaning = "Short-lived cookie (``SameSite=Lax`` / unset)"

        params.append(
            ParamInfo(
                key=f"(set-cookie) {name}",
                value="; ".join(summary_bits),
                category=CAT_HTTP_TRAFFIC,
                meaning=meaning,
                privacy_impact=impact,
                event_index=event.event_id,
            )
        )
    return params


# --- CNAME-cloak detection -------------------------------------------------
#
# A "CNAME-cloaked" tracker is served from a first-party-looking
# subdomain (e.g. ``metrics.example.com``) that DNS-resolves via a
# CNAME record to a third-party tracker collector (e.g.
# ``custom-eulerian.eulerian.net``). The browser sees a first-party
# host on every layer above DNS (HTTP Host header, TLS SNI, JS
# origin, cookie scope), so the tracker looks first-party. The
# canonical name at the end of the CNAME chain reveals the actual
# vendor.
#
# When the analyzer cannot attribute a request via its on-the-wire
# host, we re-check against the canonical name from the captured
# CNAME chain. If a module matches the canonical name, the request
# is attributed to that vendor and a ``(cname-cloak)`` ParamInfo
# documents the aliasing.


def _detect_via_cname(
    event: RequestEvent, chains: dict[str, list[str]]
) -> tuple[object, str] | None:
    """Try to match ``event`` against any module via its CNAME-chain tail.

    Returns ``(module, canonical_host)`` if a module matches the
    canonical name (last entry of a multi-element chain), or ``None``
    if the host has no chain, the chain is trivial, or no module
    matches the canonical name.
    """
    chain = chains.get(event.host.lower())
    if not chain or len(chain) <= 1:
        return None
    canonical = chain[-1]
    if not canonical or canonical == event.host.lower():
        return None
    aliased = replace(event, host=canonical)
    for module in all_modules():
        if module.matches(aliased):
            return module, canonical
    return None


def _dedup_key(hit: Hit) -> tuple[str, str, frozenset[str], str]:
    """Return the dedup key for one hit.

    Endpoint normalization strips the query string and fragment so that
    two hits to the same URL path with different parameter *values* but
    the same key-set collapse into one representative.
    """
    parsed = urlparse(hit.url)
    endpoint = parsed._replace(query="", fragment="").geturl()
    param_keys = frozenset(p.key for p in hit.params)
    return (hit.module_id, endpoint, param_keys, _REQUEST_EVENT_TYPE)


def _registrable(url_or_host: str) -> str:
    """Return the registrable (eTLD+1) domain for a URL or bare host."""
    ext = tldextract.extract(url_or_host)
    return ".".join(p for p in (ext.domain, ext.suffix) if p)


def _is_top_level_context(context_id) -> bool:
    """Return ``True`` when ``context_id`` is a top-level browsing context.

    geckodriver/BiDi assigns UUID-shaped ids to top-level contexts (tabs,
    popups) and purely-numeric ids to child frames (iframes). A page the
    visitor navigated *to* in a top-level context is first-party; an iframe
    that merely loaded inside a page (cookiebot CMP, reCAPTCHA, a YouTube
    embed) is not.
    """
    if not context_id:
        return False
    return not str(context_id).isdigit()


@dataclass
class Analysis:
    """The result of running tracker modules over a bundle.

    ``hits`` is the raw, in-order list — one entry per matched request.
    ``untracked_requests`` holds the request events that no module
    claimed; reporters use it (gated by ``--debug``) to surface
    candidate trackers worth adding a module for.

    Reporters can either consume :attr:`hits` directly (for JSON
    drill-down) or fold it through :meth:`representative_hits` for
    human-readable output.
    """

    manifest: Manifest
    hits: list[Hit] = field(default_factory=list)
    untracked_requests: list[RequestEvent] = field(default_factory=list)
    #: DNS-posture snapshot of the capture's first-party domain. Populated
    #: by :func:`analyze_bundle`; left ``None`` by :func:`analyze_events`
    #: (which doesn't perform network lookups so tests stay hermetic).
    dns_posture: DNSPosture | None = None
    #: Top-level pages the visitor navigated to during the session, in
    #: first-seen order. Only *top-level* browsing contexts count (tabs /
    #: popups); embedded iframes are excluded. These are the pages the
    #: visitor was actually on, so a request to any of their domains is
    #: first-party — not a third-party tracker. See
    #: :meth:`first_party_domains`.
    visited_pages: list[str] = field(default_factory=list)
    #: Every ``Set-Cookie`` observed during the capture, with lifetime
    #: + security-flag metadata parsed out. Built by :func:`analyze_events`
    #: as it walks each response; reporters consume via
    #: :attr:`ReportDocument.cookies`.
    cookies: list = field(default_factory=list)
    #: ``localStorage`` / ``sessionStorage`` entries observed across all
    #: ``storage_snapshot`` events, collapsed to end-of-session state per
    #: ``(origin, kind, key)``. Reporters consume via
    #: :attr:`ReportDocument.storage`.
    storage: list = field(default_factory=list)
    #: Best-effort CMS / web-platform fingerprint built from request URLs,
    #: response headers, and cookies. ``None`` when no platform signature
    #: was observed. Reporters consume via :attr:`ReportDocument.cms_fingerprint`.
    cms_fingerprint: object = None
    #: HTTP/HTTPS transport posture of the captured host (and its
    #: apex/www alternate when applicable). Populated at analysis time
    #: by :func:`analyze_bundle`'s small probe — reflects the
    #: **current** transport state of the domain, not the moment-of-
    #: capture state (which may differ for old bundles). ``None`` when
    #: the bundle didn't carry enough info, or when ``analyze_events``
    #: was called directly (no network in hermetic mode).
    transport_posture: object = None
    #: TLS-quality posture of the landing host (certificate validity/
    #: expiry, negotiated protocol/cipher, deprecated-protocol
    #: acceptance), from the stored enrichment. ``None`` when the bundle
    #: carries no enrichment or predates the TLS probe.
    tls_posture: object = None
    #: CNAME chains captured for every host the visitor contacted.
    #: ``{lowercase_host: [host, alias_1, ..., final_canonical]}``.
    #: Carried on the Analysis so the report-builder can look up the
    #: CDN/edge provider for each host without re-reading the bundle.
    cname_chains: dict = field(default_factory=dict)
    #: Origins observed in ``StorageSnapshotEvent``s during the capture.
    #: The capture pipeline only snapshots top-level origins (iframe
    #: storage is deferred — see ``[[project_iframe_storage_deferred]]``),
    #: so any origin here is provably a page the visitor's browser was
    #: on. Used by :meth:`first_party_domains` as a fallback when a
    #: top-level ``NavigationEvent`` was missed (BiDi occasionally drops
    #: them on rapid same-tab navigations).
    storage_snapshot_origins: set[str] = field(default_factory=set)
    #: The session's consent state, derived from the CMP's persisted
    #: decision artifact (see :mod:`leak_inspector.analysis.consent`).
    #: ``None`` only before :func:`analyze_events` finishes.
    consent: ConsentState | None = None
    #: When the bundle's enrichment (network posture) was captured —
    #: the artifact's ISO-8601 timestamp. ``None`` when the bundle has
    #: no enrichment (posture absent; reports say so and point at the
    #: ``leak-inspector enrich`` command).
    enriched_at: str | None = None
    #: Per-section last-probe times (``enrich --refresh <section>``),
    #: keyed by canonical section id. Empty on artifacts that predate
    #: per-section timestamps; reports then fall back to ``enriched_at``.
    section_timestamps: dict[str, str] = field(default_factory=dict)
    #: Response headers of the main document — the request whose ``url``
    #: equals the manifest's ``landing_url`` — with keys lowercased.
    #: ``None`` when no such response was observed in the capture
    #: (served from cache, or BiDi didn't surface the document response);
    #: that is distinct from ``{}`` (response seen, no headers). The
    #: security score reads CSP / HSTS from here. See
    #: :func:`_extract_security_headers`.
    security_headers: dict[str, str] | None = None
    #: Third-party ``<script src>`` referenced without an SRI ``integrity``
    #: hash (a supply-chain risk), derived from the captured page-source
    #: script index. Populated by :func:`analyze_bundle`; empty for bundles
    #: that predate page-source capture. See :mod:`leak_inspector.analysis.sri`.
    missing_sri: list = field(default_factory=list)
    #: Third-party subresources referenced *with* an SRI ``integrity`` hash
    #: (a security positive), derived from the same captured script index.
    #: Populated by :func:`analyze_bundle`. See
    #: :mod:`leak_inspector.analysis.sri`.
    protected_sri: list = field(default_factory=list)
    #: RFC 9116 ``security.txt`` presence probe from the bundle's stored
    #: enrichment. ``None`` when the bundle is un-enriched or the artifact
    #: predates the probe. Actual type is
    #: :class:`leak_inspector.http_posture.security_txt.SecurityTxtProbe`.
    security_txt: object | None = None

    def first_party_domains(self) -> set[str]:
        """Registrable domains treated as first-party for this session.

        A third party is relative to the page the visitor is *on*, not the
        single domain the session started from. The first-party set is the
        union of:

        * every top-level page the visitor navigated to (:attr:`visited_pages`),
        * every origin a ``StorageSnapshotEvent`` was recorded for
          (:attr:`storage_snapshot_origins`) — covers redirect chains where
          a top-level nav event was missed but the origin was still loaded,
        * the entry the operator typed (``target_url``) and where it resolved
          after redirects (``landing_url``) — one logical entry page, so a
          redirect origin like ``museumpas.be`` (→ ``museumpassmusees.be``)
          stays first-party,
        * the manifest ``base_domain``.
        """
        regs: set[str] = set()
        for url in self.visited_pages:
            reg = _registrable(url)
            if reg:
                regs.add(reg)
        for origin in self.storage_snapshot_origins:
            reg = _registrable(origin)
            if reg:
                regs.add(reg)
        for url in (self.manifest.target_url, self.manifest.landing_url):
            if url:
                reg = _registrable(url)
                if reg:
                    regs.add(reg)
        if self.manifest.base_domain:
            regs.add(self.manifest.base_domain)
        return regs

    def is_third_party_host(self, host: str) -> bool:
        """Return ``True`` if ``host`` is third-party for this session.

        Operator-family-aware (so an operator's own auth / CDN domains stay
        first-party) and page-context-aware (so visited top-level pages and
        the redirect entry are first-party). Empty host or unknown
        first-party context returns ``False`` (cannot conclude third-party).
        """
        if not host:
            return False
        first_party = self.first_party_domains()
        if not first_party:
            return False
        host_reg = _registrable(host)
        return not any(same_operator(host_reg, fp) for fp in first_party)

    def hits_by_module(self) -> dict[str, list[Hit]]:
        """Group the raw hit list by ``module_id``, preserving order."""
        grouped: dict[str, list[Hit]] = {}
        for hit in self.hits:
            grouped.setdefault(hit.module_id, []).append(hit)
        return grouped

    def representative_hits(self) -> list[Hit]:
        """Return one hit per dedup group, in first-seen order.

        The representative is a *copy* of the first hit in its group with
        ``events`` extended to cover every collapsed event. The original
        entries in :attr:`hits` are not mutated.
        """
        groups: dict[tuple, list[Hit]] = {}
        order: list[tuple] = []
        for hit in self.hits:
            key = _dedup_key(hit)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(hit)

        representatives: list[Hit] = []
        for key in order:
            members = groups[key]
            first = members[0]
            all_event_ids = [eid for h in members for eid in h.events]
            representatives.append(replace(first, events=all_event_ids))
        return representatives


def _build_hit(
    module: TrackerModule,
    event: RequestEvent,
    cloak_canonical: str | None = None,
) -> Hit:
    """Run a module's parser over an event and decorate the resulting hit.

    Beyond the module's own parameter parsing this attaches the captured
    request/response bodies, the ambient HTTP-traffic params (IP / Referer
    / UA / Cookie / …), Set-Cookie analysis, and — when the match came via
    a CNAME alias — a HIGH-impact cloak ParamInfo. Modules don't set the
    bodies themselves; they live on the source event.
    """
    hit = module.parse(event)
    hit.request_body = event.request_body
    hit.response_body = event.response_body
    hit.params.extend(_ambient_traffic_params(event))
    hit.params.extend(_set_cookie_params(event))
    if cloak_canonical is not None:
        hit.params.append(
            ParamInfo(
                key="(cname-cloak) canonical",
                value=f"{event.host}  →  {cloak_canonical}",
                category=CAT_HTTP_TRAFFIC,
                meaning=(
                    "Tracker reached via CNAME alias — first-party-looking "
                    "host resolves to this vendor's canonical domain. "
                    "The HTTP/TLS/JS-origin layers all see the alias as "
                    "first-party, bypassing tracker-protection lists and "
                    "third-party-cookie restrictions."
                ),
                privacy_impact=IMPACT_HIGH,
                event_index=event.event_id,
            )
        )
    return hit


def analyze_events(
    manifest: Manifest,
    events: Iterable[Event],
    cname_chains: dict[str, list[str]] | None = None,
    host_enricher: Callable[[str], IPInfo | None] | None = None,
) -> Analysis:
    """Run every registered module over an iterable of events.

    Non-request events are skipped. Request events that no module
    claims via their on-the-wire host fall through to CNAME-cloak
    detection (if ``cname_chains`` is provided): the canonical name
    from the host's CNAME chain is re-tested against each module, and
    a match attributes the request with a ``(cname-cloak)`` ParamInfo.
    Events still unclaimed after that step are stashed on
    :attr:`Analysis.untracked_requests` so the debug reporter can
    surface them as candidate trackers.

    ``cname_chains`` is a dict ``{lowercase_hostname: [chain, …]}`` as
    returned by :attr:`BundleReader.cname_chains`. Passing ``None`` or
    an empty dict disables cloak-detection — used by tests and by
    bundles produced before the feature existed.
    """
    chains = cname_chains or {}
    hits: list[Hit] = []
    untracked: list[RequestEvent] = []
    visited_pages: list[str] = []
    # Side-channel: every RequestEvent we saw, plus the module that
    # claimed it (None when untracked). Used at the end to extract
    # CookieEntries with first-party-ness resolved against the final
    # visited-pages set. Same-host attribution may upgrade some
    # untracked events to hits — we patch the mapping below.
    event_module_pairs: list[tuple[RequestEvent, TrackerModule | None]] = []
    storage_snapshots: list[StorageSnapshotEvent] = []
    all_requests: list[RequestEvent] = []
    for event in events:
        # Track top-level navigations: these are the pages the visitor was
        # actually on, which define the first-party context (see
        # Analysis.first_party_domains). Iframe navigations are excluded.
        if isinstance(event, NavigationEvent):
            if (
                _is_top_level_context(event.context_id)
                and event.url
                and event.url not in visited_pages
            ):
                visited_pages.append(event.url)
            continue
        if isinstance(event, StorageSnapshotEvent):
            storage_snapshots.append(event)
            continue
        if not isinstance(event, RequestEvent):
            continue
        all_requests.append(event)
        module = detect(event)
        cloak_canonical: str | None = None
        if module is None and chains:
            cloak_match = _detect_via_cname(event, chains)
            if cloak_match is not None:
                module, canonical = cloak_match
                # The cloak marker means "a tracker is hiding behind
                # first-party DNS to evade blocklists" — it drives the
                # privacy evasion penalty and third-party attribution.
                # A government / para-government module matched via CNAME
                # is the site's *own* public-sector host (e.g. a Walloon
                # commune on IMIO), not a cloaked tracker: attribute it
                # for the report, but don't mark it as evasion.
                if getattr(module, "module_kind", MODULE_KIND_TRACKER) == MODULE_KIND_TRACKER:
                    cloak_canonical = canonical
        event_module_pairs.append((event, module))
        if module is None:
            untracked.append(event)
            continue
        # CNAME-cloak attribution (when cloak_canonical is set) surfaces the
        # first-party-looking alias as a HIGH-impact ParamInfo. The hit's
        # ``host`` field stays as the on-the-wire name; the canonical name is
        # documented on that param.
        hits.append(_build_hit(module, event, cloak_canonical))

    # Same-host attribution for Matomo. A host that served the Matomo collect
    # endpoint (/matomo.php or /piwik.php) is a dedicated Matomo instance, so
    # its other requests — the Matomo Tag Manager container
    # (/js/container_<hash>.js), plugin endpoints, … — are the same Matomo and
    # are attributed to it rather than left unclassified. The loader
    # (/matomo.js) is deliberately NOT a confirmation signal: sites commonly
    # proxy it through their own first-party domain, which must not be treated
    # as a dedicated Matomo host.
    matomo_collector_hosts = {
        hit.host
        for hit in hits
        if hit.module_id == "matomo"
        and urlparse(hit.url).path.endswith(("/matomo.php", "/piwik.php"))
    }
    # The Matomo Tag Manager container (/js/container_<id>.js) is distinctive
    # enough to confirm a self-hosted Matomo host on its own — it commonly
    # loads before (or without) the first /matomo.php collect hit, e.g. on
    # bulk captures that end before any tracked action fires.
    matomo_collector_hosts |= {
        event.host
        for event in untracked
        if is_mtm_container_path(urlparse(event.url).path)
    }
    if matomo_collector_hosts:
        matomo = next((m for m in all_modules() if m.module_id == "matomo"), None)
        if matomo is not None:
            still_untracked: list[RequestEvent] = []
            for event in untracked:
                if event.host in matomo_collector_hosts:
                    hits.append(_build_hit(matomo, event))
                else:
                    still_untracked.append(event)
            untracked = still_untracked
            # Re-attributed hits were appended at the end; restore stream order.
            hits.sort(key=lambda h: h.events[0] if h.events else 0)

    # Same-host attribution for Plausible. A host that served the
    # ``/api/event`` collect endpoint with the documented JSON body is a
    # confirmed Plausible instance. Generic loader paths like
    # ``/js/script.js`` on that same host then attribute to Plausible too —
    # the module's own ``matches()`` is intentionally conservative about
    # claiming ``/js/script.js`` on arbitrary hosts (the filename is too
    # common to claim universally).
    plausible_collector_hosts = {
        hit.host
        for hit in hits
        if hit.module_id == "plausible"
        and urlparse(hit.url).path == "/api/event"
    }
    if plausible_collector_hosts:
        plausible = next((m for m in all_modules() if m.module_id == "plausible"), None)
        if plausible is not None:
            still_untracked: list[RequestEvent] = []
            for event in untracked:
                if event.host in plausible_collector_hosts:
                    hits.append(_build_hit(plausible, event))
                else:
                    still_untracked.append(event)
            untracked = still_untracked
            hits.sort(key=lambda h: h.events[0] if h.events else 0)

    # Same-host attribution for Google First-Party Mode proxies. A host
    # that served any FP-Mode-specific path (``/g/collect`` with G-* tid,
    # ``/_/set_cookie``, ``/_/service_worker/...``) is a confirmed
    # operator-owned Google tagging server. Generic loader paths like
    # ``/main.js`` then attribute to the same module — the standalone
    # ``main.js`` filename is too common to claim by path alone.
    fp_mode_collector_hosts = {
        hit.host for hit in hits if hit.module_id == "google_first_party_mode"
    }
    if fp_mode_collector_hosts:
        fp_mode = next(
            (m for m in all_modules() if m.module_id == "google_first_party_mode"),
            None,
        )
        if fp_mode is not None:
            still_untracked: list[RequestEvent] = []
            for event in untracked:
                if event.host in fp_mode_collector_hosts:
                    hits.append(_build_hit(fp_mode, event))
                else:
                    still_untracked.append(event)
            untracked = still_untracked
            hits.sort(key=lambda h: h.events[0] if h.events else 0)

    # ASN / country enrichment for self-hosted collector hosts. Hosted
    # SaaS hosts live under known vendor infrastructure — no useful signal
    # from looking them up. Self-hosted instances are the interesting case:
    # the ASN tells us who has technical control over the data.
    #
    # Per-module collector-host sets:
    #   * Matomo — only hosts that served /matomo.php or /piwik.php, to
    #     exclude first-party-proxied /matomo.js loaders that aren't
    #     actually Matomo instances.
    #   * Snowplow — any non-hosted Snowplow hit, since the module's
    #     detection (path + tp signature + Iglu body schema) is already
    #     strict enough that any match is a confirmed collector.
    #   * Plausible — any non-hosted Plausible hit. The module's matches()
    #     is already strict (hosted family / ``plausible.`` subdomain +
    #     plausible-shaped path / ``/api/event`` with documented body
    #     schema / legacy ``/js/plausible.js`` filename), so any match is
    #     a confirmed collector for enrichment purposes.
    self_hosted_collectors: dict[str, tuple[set[str], str, str]] = {
        "matomo": (
            {h for h in matomo_collector_hosts if not is_hosted_matomo_host(h)},
            "Matomo", "InnoCraft Ltd",
        ),
        "snowplow": (
            {
                hit.host for hit in hits
                if hit.module_id == "snowplow"
                and not is_hosted_snowplow_host(hit.host)
            },
            "Snowplow", "Snowplow Analytics Ltd",
        ),
        "plausible": (
            {
                hit.host for hit in hits
                if hit.module_id == "plausible"
                and not is_hosted_plausible_host(hit.host)
            },
            "Plausible", "Plausible Insights OÜ",
        ),
    }
    if host_enricher is not None:
        # Collect the union of distinct collector hosts in stable order
        # (sorted) so behaviour is deterministic across runs. Apply the
        # global cap to defeat amplification: a hostile bundle with
        # thousands of fabricated collector hostnames would otherwise
        # fan out N DNS + N WHOIS queries per analysis.
        unique_hosts: list[str] = sorted({
            host
            for hosts, _, _ in self_hosted_collectors.values()
            for host in hosts
        })
        enriched_hosts: set[str] = set(unique_hosts[:ENRICH_HOST_CAP])
        dropped_hosts: set[str] = set(unique_hosts[ENRICH_HOST_CAP:])
        enrich_cache: dict[str, IPInfo | None] = {
            host: host_enricher(host) for host in enriched_hosts
        }
        first_dropped_hit_seen = False
        for hit in hits:
            spec = self_hosted_collectors.get(hit.module_id)
            if spec is None:
                continue
            hosts, friendly, vendor = spec
            if hit.host not in hosts:
                continue
            if hit.host in dropped_hosts:
                # Surface the cap on the first dropped hit so it's visible
                # in the report — silent truncation reads as "covered
                # everything" when it didn't.
                if not first_dropped_hit_seen:
                    first_dropped_hit_seen = True
                    hit.params.append(
                        ParamInfo(
                            key="(infra) enrichment_capped",
                            value=(
                                f"{len(dropped_hosts)} collector host"
                                f"{'s' if len(dropped_hosts) != 1 else ''} "
                                f"skipped — per-analysis cap of "
                                f"{ENRICH_HOST_CAP} reached"
                            ),
                            category=CAT_HTTP_TRAFFIC,
                            meaning=(
                                "ASN / country enrichment is capped per "
                                "analysis to defeat DNS/WHOIS amplification "
                                "via fabricated collector hostnames. The "
                                "first hosts (sorted) were enriched; the "
                                "remainder were skipped."
                            ),
                            privacy_impact=IMPACT_LOW,
                            event_index=hit.events[0] if hit.events else 0,
                        )
                    )
                continue
            info = enrich_cache.get(hit.host)
            if info is None:
                continue
            hit.params.append(
                ParamInfo(
                    key="(infra) hosting",
                    value=_format_ipinfo(info),
                    category=CAT_HTTP_TRAFFIC,
                    meaning=(
                        f"IP + ASN org currently serving this {friendly} "
                        f"collector. For a self-hosted instance this — not "
                        f"{vendor} — is who has technical control over the data."
                    ),
                    privacy_impact=IMPACT_MEDIUM,
                    event_index=hit.events[0] if hit.events else 0,
                )
            )

    storage_snapshot_origins = {
        snap.origin for snap in storage_snapshots if snap.origin
    }
    security_headers = _extract_security_headers(manifest, all_requests)
    analysis = Analysis(
        manifest=manifest,
        hits=hits,
        untracked_requests=untracked,
        visited_pages=visited_pages,
        storage_snapshot_origins=storage_snapshot_origins,
        security_headers=security_headers,
    )

    # Same-host attribution above may have upgraded events that were
    # originally untracked into hits. Refresh the per-event module
    # mapping so cookies inherit the (now-resolved) vendor label.
    hits_by_event_id: dict[int, Hit] = {}
    for hit in hits:
        for ev_id in hit.events:
            hits_by_event_id[ev_id] = hit
    fp_domains = analysis.first_party_domains()
    # Dedup by (name, host) — the same cookie typically gets re-set
    # multiple times across a session (every embedded resource that
    # loads from the issuing host echoes its Set-Cookie). Keep the
    # last write, matching browser semantics: the most recent
    # Set-Cookie wins, including its attributes.
    cookies_by_identity: dict[tuple[str, str], object] = {}
    for ev, original_module in event_module_pairs:
        upgraded_hit = hits_by_event_id.get(ev.event_id)
        if upgraded_hit is not None:
            vendor = upgraded_hit.module_name
        elif original_module is not None:
            vendor = original_module.module_name
        else:
            vendor = ev.host
        is_first_party = not analysis.is_third_party_host(ev.host)
        for entry in _extract_set_cookie_entries(
            ev, is_first_party=is_first_party, vendor=vendor,
        ):
            cookies_by_identity[(entry.name, entry.host)] = entry
    # Stable order: first-party first (operator's own house), then by
    # host, then by name. Reads naturally as "cookies your own site
    # sets" followed by "cookies the third parties set".
    analysis.cookies = sorted(
        cookies_by_identity.values(),
        key=lambda c: (not c.is_first_party, c.host, c.name),
    )
    analysis.storage = _collapse_storage_snapshots(storage_snapshots)
    analysis.consent = derive_consent_state(
        storage_snapshots, hits, analysis.is_third_party_host,
    )
    analysis.cms_fingerprint = _build_cms_fingerprint(all_requests)
    analysis.cname_chains = dict(chains)
    _stamp_cdn_providers(analysis, chains)
    return analysis


def _stamp_cdn_providers(analysis: Analysis, chains: dict) -> None:
    """Stamp ``Hit.cdn_provider`` for every hit whose host has a CNAME tail.

    Pure data lookup against the curated provider table — see
    :mod:`leak_inspector.cname_provider`. Hits whose host has no
    CNAME chain (or whose chain tail isn't seeded) get ``None``.
    """
    from ..cname_provider import cname_provider_from_chain

    for hit in analysis.hits:
        chain = chains.get((hit.host or "").lower())
        if chain:
            hit.cdn_provider = cname_provider_from_chain(chain)


def _extract_security_headers(
    manifest: Manifest, requests: list[RequestEvent]
) -> dict[str, str] | None:
    """Return the main document's response headers, keys lowercased.

    The main document is the request whose ``url`` equals the
    manifest's ``landing_url`` — the only certain way to pick the
    document response (a ``RequestEvent`` carries no resource-type).
    Returns ``None`` when no such response was observed; an empty dict
    means the response was seen but carried no headers.
    """
    landing = manifest.landing_url
    if not landing:
        return None
    for event in requests:
        if event.url == landing:
            return {k.lower(): v for k, v in (event.response_headers or {}).items()}
    return None


def _build_cms_fingerprint(events: list[RequestEvent]):
    """Run the passive CMS detector over the captured requests.

    Returns a raw :class:`CMSFingerprint` (or ``None`` when no platform
    matched) — no version probe, no EOL judgment. The probe lives in
    :func:`analyze_bundle` (it's a network call and should not run
    during hermetic ``analyze_events`` tests); the EOL judgment lives
    in :func:`build_report_document` (it's render-time, depends on
    today's date).
    """
    from ..cms import detect_cms

    return detect_cms(events)


def _collapse_storage_snapshots(
    snapshots: list[StorageSnapshotEvent],
) -> list:
    """Collapse storage_snapshot events into end-of-session StorageEntries.

    The site re-snapshots each origin's storage periodically; only the
    final state per ``(origin, kind, key)`` matters for the report.
    Cookies (the ``"cookie"`` snapshot kind) are intentionally excluded
    here — they have their own section built from ``Set-Cookie``
    headers, which carries the security-flag + lifetime metadata that
    the JS-visible ``document.cookie`` strips.

    Returns a list of :class:`StorageEntry` sorted by
    ``(origin, kind, key)`` for a stable, diff-friendly order.
    """
    from ..report.document import StorageEntry

    latest: dict[tuple[str, str, str], StorageEntry] = {}
    for snap in snapshots:
        if snap.kind not in ("local", "session"):
            continue
        for entry in snap.entries or []:
            key = entry.get("key")
            if not key:
                continue
            value = entry.get("value") or ""
            latest[(snap.origin, snap.kind, key)] = StorageEntry(
                origin=snap.origin,
                kind=snap.kind,
                key=key,
                value_bytes=len(str(value).encode("utf-8")),
            )
    return sorted(
        latest.values(),
        key=lambda e: (e.origin, e.kind, e.key),
    )


def _iso_to_epoch(ts: str | None) -> float | None:
    """Parse an ISO-8601 ``…Z`` timestamp to Unix seconds, ``None`` on failure."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _collapse_document_cookies(bundle: BundleReader, analysis: "Analysis") -> list:
    """Build first-party :class:`CookieEntry` rows from the browser cookie jar.

    Capture records each origin's full first-party jar
    (``driver.get_cookies()``) into ``storage/<origin>.json``; this reads
    those snapshots back, collapses them to the end-of-session state per
    ``(origin, name)`` (last snapshot wins, mirroring
    :func:`_collapse_storage_snapshots`), and turns each into a
    ``CookieEntry``. Jar cookies are always first-party (the jar is
    origin-scoped), so they never trigger the third-party persistent
    cap. Cookies already represented by a ``Set-Cookie`` entry (same
    name + host, or any first-party name) are skipped — Set-Cookie
    carries the authoritative wire metadata. Values are never read.
    """
    existing_keys = {(c.name, c.host) for c in (analysis.cookies or [])}
    existing_fp_names = {
        c.name for c in (analysis.cookies or [])
        if getattr(c, "is_first_party", False)
    }
    collapsed: dict[tuple[str, str], object] = {}
    for origin in bundle.storage_origins():
        try:
            data = bundle.storage(origin)
        except BundleReadError:
            continue
        is_fp = not analysis.is_third_party_host(origin)
        for snap in data.get("snapshots") or []:
            ref_epoch = _iso_to_epoch(snap.get("captured_at"))
            for raw in snap.get("cookies") or []:
                entry = _jar_cookie_to_entry(
                    raw, host=origin, is_first_party=is_fp, ref_epoch=ref_epoch,
                )
                if entry is not None:
                    collapsed[(origin, entry.name)] = entry

    out = []
    for (origin, name), entry in collapsed.items():
        if (name, origin) in existing_keys:
            continue
        if entry.is_first_party and name in existing_fp_names:
            continue
        out.append(entry)
    return sorted(out, key=lambda c: (c.host, c.name))


def _format_ipinfo(info: IPInfo) -> str:
    """Render an :class:`IPInfo` as ``AS<n> <org> (<cc>)``.

    Missing fields are dropped rather than rendered as ``?`` — matches
    the dns_posture pattern of staying silent when data is missing.
    """
    parts: list[str] = []
    if info.asn is not None:
        parts.append(f"AS{info.asn}")
    if info.as_org:
        parts.append(info.as_org)
    if info.country_code:
        parts.append(f"({info.country_code})")
    return " ".join(parts)


def analyze_bundle(path: Path | str) -> Analysis:
    """Open a bundle zip and produce an :class:`Analysis` for it — offline.

    All network-derived data (DNS posture, transport posture, CMS
    version probe, per-host IP/ASN/geo) comes from the bundle's stored
    enrichment artifact, written at capture close (or retrofitted via
    ``leak-inspector enrich``). Analysis never touches the network:
    re-probing at analysis time would staple *today's* DNS onto a
    capture from another moment.

    An un-enriched bundle analyzes fine but carries no posture
    (``dns_posture`` / ``transport_posture`` stay ``None``,
    ``enriched_at`` is ``None``) — reports surface that honestly and
    point at the ``enrich`` command.
    """
    with BundleReader(path) as bundle:
        enrichment = bundle.enrichment
        host_ipinfo = enrichment.host_ipinfo if enrichment else {}
        analysis = analyze_events(
            bundle.manifest,
            bundle.events(),
            cname_chains=bundle.cname_chains,
            host_enricher=host_ipinfo.get if host_ipinfo else None,
        )
        all_scripts = [
            entry
            for _name, index in bundle.page_source_script_indexes()
            for entry in (index or [])
        ]
        page_htmls = [html for _name, html in bundle.page_sources()]
        analysis.cookies = list(analysis.cookies or []) + _collapse_document_cookies(
            bundle, analysis
        )
    analysis.missing_sri = detect_missing_sri(
        all_scripts, analysis.is_third_party_host
    )
    analysis.protected_sri = detect_protected_sri(
        all_scripts, analysis.is_third_party_host
    )
    _name_self_hosted_banners(analysis, page_htmls)
    if enrichment is not None:
        analysis.enriched_at = enrichment.enriched_at
        analysis.section_timestamps = dict(
            getattr(enrichment, "section_timestamps", {}) or {}
        )
        analysis.dns_posture = enrichment.dns_posture
        analysis.transport_posture = enrichment.transport_posture
        analysis.tls_posture = getattr(enrichment, "tls_posture", None)
        analysis.security_txt = getattr(enrichment, "security_txt", None)
        _apply_cms_probe(analysis, enrichment.cms_probe)
    return analysis


def _name_self_hosted_banners(analysis: Analysis, page_htmls: list[str]) -> None:
    """Fold any markup-detected self-hosted banner into ``consent.cmp_names``.

    Self-hosted, server-rendered banners (LCP/Icordis) leave no decodable
    decision artifact, so the consent pass never names them. Detecting the
    banner in the saved page source adds its name (presence, not decision):
    the state stays as derived — typically ``unknown`` — which the report
    renders as "banner detected … decision not machine-readable" rather
    than "no known consent banner". No-op when no banner is found or the
    consent pass did not run.
    """
    banners = detect_self_hosted_banners(page_htmls)
    if not banners or analysis.consent is None:
        return
    merged = tuple(sorted(set(analysis.consent.cmp_names) | set(banners)))
    analysis.consent = replace(analysis.consent, cmp_names=merged)


def _apply_cms_probe(analysis: Analysis, probe) -> None:
    """Apply a stored CMS version-probe result to the passive fingerprint.

    The probe ran at enrichment time (see
    :mod:`leak_inspector.enrichment.producer`); here its stored result
    upgrades the passively-detected fingerprint with the same evidence
    wording the live probe used to add. Skipped when there is no probe
    result, no passive fingerprint, a passively-found version, or a
    platform mismatch (the site changed between enrichments).
    """
    fp = analysis.cms_fingerprint
    if probe is None or fp is None or fp.version is not None:
        return
    if probe.platform != fp.name:
        return
    if probe.version:
        probe_note = f" (version probed at {probe.probe_url})"
    else:
        # Probe was attempted but blocked / 404'd. Surfacing this in
        # the evidence is itself useful — hardening the version file
        # is a security-positive signal.
        probe_note = (
            f" (version probe at {probe.probe_url} returned no result — "
            "file may be hardened/removed)"
        )
    analysis.cms_fingerprint = replace(
        fp,
        version=probe.version,
        evidence=fp.evidence + probe_note,
    )


__all__ = [
    "Analysis",
    "analyze_bundle",
    "analyze_events",
]
