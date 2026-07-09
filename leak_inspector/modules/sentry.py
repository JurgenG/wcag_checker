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

"""Sentry (error monitoring) detector.

Each captured error or transaction is POSTed to a Sentry collector with
a newline-delimited JSON ("envelope") body that routinely contains:
user identity, breadcrumbs (navigation/click history), error messages
and stack traces, and arbitrary tags.

Match strategy: hosted Sentry → ``*.sentry.io`` hitting ``/api/`` paths;
self-hosted → ``sentry_key`` + ``sentry_version`` query params (the
browser SDK's DSN-auth signature); SDK delivery → ``*.sentry-cdn.com``,
Sentry's exclusive CDN for the browser SDK loaded into the origin.
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


_SENTRY_HOST_SUFFIX = ".sentry.io"
_SENTRY_HOST_EXACT = "sentry.io"
_SENTRY_CDN_SUFFIX = ".sentry-cdn.com"


_USER_FIELDS: tuple[tuple[tuple[str, ...], str, str, str, str], ...] = (
    (("user", "email"),      "(body) user.email",
     CAT_PII, "Visitor email address attached to the error event",            IMPACT_HIGH),
    (("user", "id"),         "(body) user.id",
     CAT_PII, "Site-supplied user ID attached to the error event",            IMPACT_HIGH),
    (("user", "username"),   "(body) user.username",
     CAT_PII, "Username attached to the error event",                         IMPACT_HIGH),
    (("user", "ip_address"), "(body) user.ip_address",
     CAT_PII, "Visitor IP address (either client-provided or server-derived)", IMPACT_HIGH),
)


_PARAMS: dict[str, tuple[str, str, str]] = {
    "sentry_key":     (CAT_TECHNICAL,  "Sentry public DSN key (per-project identifier)", IMPACT_LOW),
    "sentry_secret":  (CAT_TECHNICAL,  "Sentry secret DSN key (should not appear client-side)", IMPACT_LOW),
    "sentry_version": (CAT_TECHNICAL,  "Sentry ingestion-protocol version",      IMPACT_LOW),
    "sentry_client":  (CAT_TECHNICAL,  "Sentry SDK identifier (e.g. ``sentry.javascript.browser/7.x``)", IMPACT_LOW),
    "sentry_environment": (CAT_TECHNICAL, "Sentry environment label (production / staging)", IMPACT_LOW),
    "sentry_release":     (CAT_TECHNICAL, "Sentry release identifier",            IMPACT_LOW),
}


def _parse_envelope(body: str | None) -> list[ParamInfo]:
    if not body:
        return []
    items: list[dict] = []
    for line in body.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            decoded = json.loads(stripped)
        except (ValueError, TypeError):
            continue
        if isinstance(decoded, dict):
            items.append(decoded)
    if not items:
        return []

    extracted: list[ParamInfo] = []

    for item in items:
        for path, key, category, meaning, impact in _USER_FIELDS:
            value = _walk(item, path)
            if value:
                extracted.append(ParamInfo(
                    key=key, value=str(value),
                    category=category, meaning=meaning,
                    privacy_impact=impact, event_index=0,
                ))

        exception = item.get("exception")
        if isinstance(exception, dict):
            values = exception.get("values") or []
            if isinstance(values, list) and values and isinstance(values[0], dict):
                first = values[0]
                exc_type = first.get("type")
                exc_msg = first.get("value")
                if exc_type:
                    extracted.append(ParamInfo(
                        key="(body) exception.type",
                        value=str(exc_type),
                        category=CAT_BEHAVIORAL,
                        meaning="Type of the thrown error",
                        privacy_impact=IMPACT_MEDIUM,
                        event_index=0,
                    ))
                if exc_msg:
                    truncated = str(exc_msg)[:200]
                    extracted.append(ParamInfo(
                        key="(body) exception.message",
                        value=truncated,
                        category=CAT_PII,
                        meaning=(
                            "Error message — frequently contains URLs with "
                            "tokens, variable values, or other identifying data"
                        ),
                        privacy_impact=IMPACT_HIGH,
                        event_index=0,
                    ))
                stack = first.get("stacktrace")
                frames = (stack.get("frames") if isinstance(stack, dict) else None) or []
                if isinstance(frames, list) and frames:
                    extracted.append(ParamInfo(
                        key="(body) stack_depth",
                        value=str(len(frames)),
                        category=CAT_TECHNICAL,
                        meaning="Number of stack frames captured with the error",
                        privacy_impact=IMPACT_LOW,
                        event_index=0,
                    ))

        breadcrumbs = item.get("breadcrumbs")
        if isinstance(breadcrumbs, dict):
            crumbs = breadcrumbs.get("values") or []
        elif isinstance(breadcrumbs, list):
            crumbs = breadcrumbs
        else:
            crumbs = []
        if isinstance(crumbs, list) and crumbs:
            extracted.append(ParamInfo(
                key="(body) breadcrumb_count",
                value=str(len(crumbs)),
                category=CAT_BEHAVIORAL,
                meaning=(
                    "Number of breadcrumbs (recent navigation, click, "
                    "console, XHR events — full visitor activity trail "
                    "leading up to the error)"
                ),
                privacy_impact=IMPACT_HIGH,
                event_index=0,
            ))

        request = item.get("request")
        if isinstance(request, dict):
            url = request.get("url")
            if url:
                extracted.append(ParamInfo(
                    key="(body) request.url",
                    value=str(url),
                    category=CAT_CONTENT,
                    meaning="URL where the error / transaction was recorded",
                    privacy_impact=IMPACT_MEDIUM,
                    event_index=0,
                ))

        transaction = item.get("transaction")
        if transaction:
            extracted.append(ParamInfo(
                key="(body) transaction",
                value=str(transaction),
                category=CAT_BEHAVIORAL,
                meaning="Transaction / page name (performance event)",
                privacy_impact=IMPACT_MEDIUM,
                event_index=0,
            ))

        tags = item.get("tags")
        if isinstance(tags, dict) and tags:
            sample = ", ".join(sorted(tags.keys())[:5])
            extracted.append(ParamInfo(
                key="(body) tags",
                value=f"{len(tags)} tag(s): {sample}"
                      + ("…" if len(tags) > 5 else ""),
                category=CAT_BEHAVIORAL,
                meaning="Custom tags attached to the event (values not surfaced)",
                privacy_impact=IMPACT_MEDIUM,
                event_index=0,
            ))

        release = item.get("release")
        if release:
            extracted.append(ParamInfo(
                key="(body) release",
                value=str(release),
                category=CAT_TECHNICAL,
                meaning="Application release / version identifier",
                privacy_impact=IMPACT_LOW,
                event_index=0,
            ))
        environment = item.get("environment")
        if environment:
            extracted.append(ParamInfo(
                key="(body) environment",
                value=str(environment),
                category=CAT_TECHNICAL,
                meaning="Application environment (production / staging / …)",
                privacy_impact=IMPACT_LOW,
                event_index=0,
            ))

    return extracted


def _walk(node: dict, path: tuple[str, ...]):
    cursor = node
    for key in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(key)
        if cursor is None:
            return None
    return cursor


@register
class SentryModule(TrackerModule):
    """Detect Sentry error / performance / replay collector traffic."""

    module_id = "sentry"
    module_name = "Sentry"
    vendor = "Functional Software, Inc. (Sentry)"
    legal_jurisdiction = "US"
    data_residency = "US default (sentry.io); EU instance available (de.sentry.io / eu.sentry.io)"
    sovereignty_notes = "US CLOUD Act applies regardless of EU instance choice"
    # Error monitoring: privacy 1.5 (technical telemetry — stack traces,
    #   breadcrumbs, session-tied at most, no durable visitor profile;
    #   rubric 1.5). security 2.5 (unpinned SDK in the origin). resilience
    #   2.0 (US hosted sentry.io; self-hostable but this module catches the
    #   hosted form — rubric 2.0).
    impact_rating = ImpactRating(privacy=1.5, security=2.5, resilience=2.0)
    impact_notes = {
        "privacy": "Error telemetry — stack traces and breadcrumbs tied "
            "to the session at most, no durable visitor profile.",
        "security": "Loads an unpinned SDK into your origin.",
        "resilience": "Hosted sentry.io (US); self-hostable, but this is "
            "the hosted form.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host.endswith(_SENTRY_CDN_SUFFIX):
            return True
        if host == _SENTRY_HOST_EXACT or host.endswith(_SENTRY_HOST_SUFFIX):
            path = urlparse(event.url).path
            return path.startswith("/api/")
        params = event.query_params
        return "sentry_key" in params and "sentry_version" in params

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Sentry parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key, value=value, category=category, meaning=meaning,
                    privacy_impact=impact, event_index=event.event_id,
                )
            )
        for body_param in _parse_envelope(event.request_body):
            body_param.event_index = event.event_id
            params.append(body_param)
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
