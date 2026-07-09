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

"""Plausible Analytics detector.

Plausible is self-hostable and intentionally privacy-friendly: no
cookies, no persistent visitor ID, no raw IP in the payload. To
recognise it across the wild we combine:

1. Hosted variants — ``plausible.io`` and any ``*.plausible.io``
   subdomain (Plausible Cloud, operated by Plausible Insights OÜ in
   Estonia).
2. The documented collect endpoint — ``/api/event`` POSTed with a JSON
   body whose top-level keys include ``name`` + ``url`` + ``domain``.
   That body shape is the unambiguous detection signal on any host.
3. Self-hosting convention — ``plausible.<operator-domain>`` serving a
   Plausible-shaped path (``/api/event`` or ``/js/script*.js`` or
   ``/js/plausible*.js``). The subdomain literally named ``plausible``
   is the docker-compose-recommended setup pattern.
4. Legacy filename — ``/js/plausible.js`` (older loader naming) on any
   host.

Generic ``/js/script.js`` paths on unrelated hosts are deliberately NOT
claimed — the filename alone is too common. Such loaders are picked up
by the runner's same-host attribution pass once a sibling ``/api/event``
hit confirms the host is Plausible.

Because Plausible is jurisdiction-ambiguous by default (EE for hosted
Cloud, operator-controlled for self-hosted), the class-level
``legal_jurisdiction`` is left blank. Each hit instead carries a
``(deployment) …`` ParamInfo naming the deployment mode, and the
runner attaches an ``(infra) hosting`` ParamInfo for self-hosted
collectors so the actual controller is visible.
"""

from __future__ import annotations

import json
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
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOSTED_HOST_EXACT = "plausible.io"
_HOSTED_HOST_SUFFIX = ".plausible.io"

# Self-hosting convention: subdomain literally named ``plausible.<…>``.
# Documented in Plausible's docker-compose examples.
_SELF_HOSTING_PREFIX = "plausible."

# Loader paths Plausible serves. ``/js/script.js`` is the canonical
# modern name; ``/js/plausible.js`` is the legacy name; the rest are
# feature variants documented in Plausible's tracker docs.
_LOADER_PATH_SUFFIXES_GENERIC: tuple[str, ...] = ("/plausible.js",)
_LOADER_PATH_PREFIXES_ON_PLAUSIBLE_HOST: tuple[str, ...] = (
    "/js/script.js",
    "/js/script.",       # /js/script.outbound-links.js, /js/script.hash.js, …
    "/js/plausible.js",
    "/js/plausible.",
)

_COLLECT_PATH = "/api/event"

# Top-level JSON keys that the documented Plausible body must include.
# Detection requires all three so unrelated ``/api/event`` endpoints
# (e.g. analytics tools that happen to share the path) are rejected.
_BODY_REQUIRED_KEYS = frozenset({"name", "url", "domain"})


def is_hosted_plausible_host(host: str) -> bool:
    """True iff ``host`` is Plausible Insights OÜ's hosted Cloud.

    Public helper so the analysis runner can decide whether to enrich a
    confirmed Plausible collector with ASN / country (only self-hosted
    deployments need that — Plausible Cloud lives under known
    infrastructure).
    """
    host = host.lower()
    return host == _HOSTED_HOST_EXACT or host.endswith(_HOSTED_HOST_SUFFIX)


def _starts_with_plausible_subdomain(host: str) -> bool:
    return host.lower().startswith(_SELF_HOSTING_PREFIX)


def _looks_like_plausible_loader_path(path: str) -> bool:
    return any(path.startswith(p) for p in _LOADER_PATH_PREFIXES_ON_PLAUSIBLE_HOST)


def _body_has_plausible_schema(body: str | None) -> bool:
    """True iff ``body`` is JSON with the documented ``name``/``url``/``domain`` keys."""
    if not body:
        return False
    try:
        decoded = json.loads(body)
    except (ValueError, TypeError):
        return False
    if not isinstance(decoded, dict):
        return False
    return _BODY_REQUIRED_KEYS.issubset(decoded.keys())


# Body field classification. Plausible's body is minimal by design —
# no cookies, no visitor pseudonym, no fingerprinting surface.
_BODY_FIELDS: tuple[tuple[str, str, str, str, str], ...] = (
    ("name",     "(body) name",     CAT_BEHAVIORAL,
     "Event name — ``pageview`` (default) or a custom event the operator chose",  IMPACT_MEDIUM),
    ("url",      "(body) url",      CAT_CONTENT,
     "Full page URL the event fired on",                                          IMPACT_MEDIUM),
    ("domain",   "(body) domain",   CAT_TECHNICAL,
     "Plausible site identifier the visit is attributed to (or comma-separated for multi-site)", IMPACT_LOW),
    ("referrer", "(body) referrer", CAT_CONTENT,
     "Document referrer",                                                         IMPACT_MEDIUM),
)


def _parse_body(body: str | None) -> list[ParamInfo]:
    if not body:
        return []
    try:
        decoded = json.loads(body)
    except (ValueError, TypeError):
        return []
    if not isinstance(decoded, dict):
        return []

    out: list[ParamInfo] = []
    for key, label, category, meaning, impact in _BODY_FIELDS:
        value = decoded.get(key)
        if value in (None, ""):
            continue
        out.append(ParamInfo(
            key=label, value=str(value),
            category=category, meaning=meaning,
            privacy_impact=impact, event_index=0,
        ))

    props = decoded.get("props")
    if isinstance(props, dict) and props:
        # Operator-chosen properties — surface field names only, never values.
        # Names can hint at PII (``email``, ``user_id``); values may contain it
        # but we don't disclose them in the report.
        keys = sorted(props.keys())
        preview = ", ".join(keys[:8]) + ("…" if len(keys) > 8 else "")
        out.append(ParamInfo(
            key="(body) props",
            value=preview,
            category=CAT_BEHAVIORAL,
            meaning=(
                "Operator-chosen custom-event properties (field names only; "
                "values intentionally not surfaced)"
            ),
            privacy_impact=IMPACT_MEDIUM,
            event_index=0,
        ))

    revenue = decoded.get("revenue")
    if isinstance(revenue, dict) and revenue:
        amount = revenue.get("amount")
        currency = revenue.get("currency")
        rendered = " ".join(part for part in [str(amount or ""), str(currency or "")] if part)
        out.append(ParamInfo(
            key="(body) revenue",
            value=rendered or "(set)",
            category=CAT_BEHAVIORAL,
            meaning="Ecommerce conversion value attached to the event",
            privacy_impact=IMPACT_MEDIUM,
            event_index=0,
        ))

    return out


@register
class PlausibleModule(TrackerModule):
    """Detect Plausible Analytics across hosted Cloud and self-hosted deployments."""

    module_id = "plausible"
    module_name = "Plausible Analytics"
    vendor = "Plausible Insights OÜ"
    # Jurisdiction is per-instance — see the ``(deployment) …`` ParamInfo
    # each hit carries. Class-level fields stay blank so the report doesn't
    # bucket self-hosted instances under Plausible Insights' EE.
    legal_jurisdiction = ""
    data_residency = ""
    sovereignty_notes = ""
    # BASE = self-hosted Plausible: privacy 1.5 — cookieless, no
    # persistent visitor ID, aggregate counts only = anonymous technical
    # telemetry (rubric privacy 1.5), below Matomo's profiling 2.0.
    # security 0.0 / resilience 0.0 (operator-run). Hosted plausible.io
    # (EU) is a Phase-5 variant (security ~1.0, resilience ~1.0); privacy
    # stays 1.5 either way (cookieless by design).
    impact_rating = ImpactRating(privacy=1.5, security=0.0, resilience=0.0)
    impact_notes = {
        "privacy": "Cookieless, no persistent visitor ID — aggregate "
            "counts only; self-hosted, so even that stays first-party.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if is_hosted_plausible_host(host):
            return True
        path = urlparse(event.url).path
        # Legacy distinctive loader filename — claim on any host.
        if any(path.endswith(s) for s in _LOADER_PATH_SUFFIXES_GENERIC):
            return True
        # Self-hosting convention: ``plausible.<…>`` + Plausible-shaped path.
        if _starts_with_plausible_subdomain(host) and (
            _looks_like_plausible_loader_path(path) or path == _COLLECT_PATH
        ):
            return True
        # The body schema is the strong on-any-host signal for /api/event.
        if path == _COLLECT_PATH and _body_has_plausible_schema(event.request_body):
            return True
        return False

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            params.append(ParamInfo(
                key=key, value=value,
                category=CAT_OTHER, meaning="Unrecognized Plausible parameter",
                privacy_impact=IMPACT_LOW, event_index=event.event_id,
            ))
        for body_param in _parse_body(event.request_body):
            body_param.event_index = event.event_id
            params.append(body_param)
        params.append(_deployment_param(event))
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )


def _deployment_param(event: RequestEvent) -> ParamInfo:
    """Per-hit deployment-mode annotation.

    Plausible Cloud (``plausible.io`` family) is operated by Plausible
    Insights OÜ in Estonia (EU); the company is GDPR-bound and runs the
    service from European infrastructure. Everything else is a
    self-hosted instance controlled by whoever runs the collector — the
    ``(infra) hosting`` ParamInfo added by the runner names that
    operator's hosting provider.
    """
    if is_hosted_plausible_host(event.host):
        return ParamInfo(
            key="(deployment) Plausible Cloud",
            value=event.host,
            category=CAT_OTHER,
            meaning=(
                "Plausible Cloud (hosted by Plausible Insights OÜ in "
                "Estonia, EE). EU-only infrastructure; GDPR-bound; no "
                "cookies / no persistent visitor ID by product design."
            ),
            privacy_impact=IMPACT_MEDIUM,
            event_index=event.event_id,
        )
    return ParamInfo(
        key="(deployment) self-hosted",
        value=event.host,
        category=CAT_OTHER,
        meaning=(
            "Self-hosted Plausible — data goes to the site operator "
            "running this collector, not to Plausible Insights OÜ. "
            "See the ``(infra) hosting`` ParamInfo for the actual "
            "ASN / country."
        ),
        privacy_impact=IMPACT_LOW,
        event_index=event.event_id,
    )
