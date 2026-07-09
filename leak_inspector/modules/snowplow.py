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

"""Snowplow Analytics detector.

Self-hostable: host-based matching alone is not enough. Combines four
signals: hosted suffixes, canonical paths, ``tv`` + ``e`` Tracker
Protocol query signature (rejecting AppNexus's ``/vevent`` collision
via the closed event-code set), and the tp2 body's Iglu schema marker.

Because Snowplow is jurisdiction-ambiguous by default (UK for hosted
BDP, operator-controlled for self-hosted), the class-level
``legal_jurisdiction`` is left blank. Each hit instead carries a
``(deployment) …`` ParamInfo naming the deployment mode, and the
runner attaches an ``(infra) hosting`` ParamInfo for self-hosted
collectors so the actual controller is visible.
"""

from __future__ import annotations

import base64
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


_HOSTED_SUFFIXES: tuple[str, ...] = (
    ".snplow.net",
    ".snowplowanalytics.com",
)


def is_hosted_snowplow_host(host: str) -> bool:
    """True iff ``host`` belongs to a Snowplow-operated BDP suffix.

    Public helper so the analysis runner can decide whether to enrich a
    confirmed Snowplow collector with ASN / country (only self-hosted
    deployments need that — hosted instances live under Snowplow's
    known infrastructure).
    """
    host = host.lower()
    return any(host.endswith(suffix) for suffix in _HOSTED_SUFFIXES)

_PATH_SUFFIXES: tuple[str, ...] = (
    "/com.snowplowanalytics.snowplow/tp2",
    "/r/tp2",
)

_BODY_SCHEMA_MARKER: str = "iglu:com.snowplowanalytics.snowplow/payload_data/"

_EVENT_CODES: frozenset[str] = frozenset({
    "pv", "pp", "se", "ue", "tr", "ti", "ad",
})


_PARAMS: dict[str, tuple[str, str, str]] = {
    "aid":    (CAT_TECHNICAL,  "Application ID — the Snowplow ``aid`` for this site", IMPACT_LOW),
    "nuid":   (CAT_IDENTIFIER, "Network user ID — server-set persistent visitor pseudonym", IMPACT_HIGH),
    "duid":   (CAT_IDENTIFIER, "Domain user ID — first-party cookie set client-side",  IMPACT_HIGH),
    "tnuid":  (CAT_IDENTIFIER, "Tracker network user ID",                              IMPACT_HIGH),
    "sid":    (CAT_IDENTIFIER, "Session ID",                                           IMPACT_MEDIUM),
    "vid":    (CAT_IDENTIFIER, "Visit / session index for this visitor",               IMPACT_MEDIUM),
    "eid":    (CAT_IDENTIFIER, "Per-event UUID (not visitor-stable)",                  IMPACT_LOW),
    "fp":     (CAT_IDENTIFIER, "Browser fingerprint",                                  IMPACT_HIGH),
    "uid":    (CAT_PII,        "Site-supplied user ID — often a real account id",     IMPACT_HIGH),
    "ip":     (CAT_PII,        "Client-IP override",                                   IMPACT_HIGH),
    "url":  (CAT_CONTENT, "Page URL the event fired on",                               IMPACT_MEDIUM),
    "refr": (CAT_CONTENT, "Document referrer",                                         IMPACT_MEDIUM),
    "page": (CAT_CONTENT, "Page title",                                                IMPACT_LOW),
    "e": (CAT_BEHAVIORAL, "Event type (pv / pp / se / ue / tr / ti / ad)",             IMPACT_MEDIUM),
    "se_ca": (CAT_BEHAVIORAL, "Structured-event category",                             IMPACT_MEDIUM),
    "se_ac": (CAT_BEHAVIORAL, "Structured-event action",                               IMPACT_MEDIUM),
    "se_la": (CAT_BEHAVIORAL, "Structured-event label",                                IMPACT_MEDIUM),
    "se_pr": (CAT_BEHAVIORAL, "Structured-event property",                             IMPACT_MEDIUM),
    "se_va": (CAT_BEHAVIORAL, "Structured-event value",                                IMPACT_MEDIUM),
    "co":    (CAT_BEHAVIORAL, "Custom-context payload (JSON list of self-describing entities)", IMPACT_HIGH),
    "cx":    (CAT_BEHAVIORAL, "Custom-context payload (base64-encoded JSON)",          IMPACT_HIGH),
    "ue_pr": (CAT_BEHAVIORAL, "Unstructured-event property (JSON, schema-bound)",      IMPACT_HIGH),
    "ue_px": (CAT_BEHAVIORAL, "Unstructured-event property (base64-encoded JSON)",     IMPACT_HIGH),
    "pp_mix": (CAT_BEHAVIORAL, "Page-ping min X scroll position",                      IMPACT_LOW),
    "pp_max": (CAT_BEHAVIORAL, "Page-ping max X scroll position",                      IMPACT_LOW),
    "pp_miy": (CAT_BEHAVIORAL, "Page-ping min Y scroll position",                      IMPACT_LOW),
    "pp_may": (CAT_BEHAVIORAL, "Page-ping max Y scroll position",                      IMPACT_LOW),
    "tr_id": (CAT_BEHAVIORAL, "Ecommerce transaction ID",                              IMPACT_MEDIUM),
    "tr_af": (CAT_BEHAVIORAL, "Transaction affiliation",                               IMPACT_LOW),
    "tr_tt": (CAT_BEHAVIORAL, "Transaction total value",                               IMPACT_MEDIUM),
    "tr_tx": (CAT_BEHAVIORAL, "Transaction tax",                                       IMPACT_LOW),
    "tr_sh": (CAT_BEHAVIORAL, "Transaction shipping",                                  IMPACT_LOW),
    "tr_ci": (CAT_BEHAVIORAL, "Transaction city",                                      IMPACT_LOW),
    "tr_st": (CAT_BEHAVIORAL, "Transaction state",                                     IMPACT_LOW),
    "tr_co": (CAT_BEHAVIORAL, "Transaction country",                                   IMPACT_LOW),
    "tr_cu": (CAT_BEHAVIORAL, "Transaction currency",                                  IMPACT_LOW),
    "ti_id": (CAT_BEHAVIORAL, "Ecommerce item: parent transaction ID",                 IMPACT_MEDIUM),
    "ti_sk": (CAT_BEHAVIORAL, "Ecommerce item: SKU",                                   IMPACT_MEDIUM),
    "ti_na": (CAT_BEHAVIORAL, "Ecommerce item: name",                                  IMPACT_MEDIUM),
    "ti_ca": (CAT_BEHAVIORAL, "Ecommerce item: category",                              IMPACT_LOW),
    "ti_pr": (CAT_BEHAVIORAL, "Ecommerce item: price",                                 IMPACT_MEDIUM),
    "ti_qu": (CAT_BEHAVIORAL, "Ecommerce item: quantity",                              IMPACT_LOW),
    "ti_cu": (CAT_BEHAVIORAL, "Ecommerce item: currency",                              IMPACT_LOW),
    "tv":     (CAT_TECHNICAL, "Tracker version (e.g. ``js-3.x.x``)",                   IMPACT_LOW),
    "cv":     (CAT_TECHNICAL, "Collector version",                                     IMPACT_LOW),
    "tna":    (CAT_TECHNICAL, "Tracker namespace",                                     IMPACT_LOW),
    "p":      (CAT_TECHNICAL, "Platform (web / mob / pc / srv / app / cnsl / iot / tv)", IMPACT_LOW),
    "dtm":    (CAT_TECHNICAL, "Device timestamp (epoch ms)",                           IMPACT_LOW),
    "stm":    (CAT_TECHNICAL, "Sent timestamp (epoch ms)",                             IMPACT_LOW),
    "ttm":    (CAT_TECHNICAL, "True timestamp (epoch ms)",                             IMPACT_LOW),
    "ctype":  (CAT_TECHNICAL, "Request content type",                                  IMPACT_LOW),
    "tz":     (CAT_TECHNICAL, "Browser timezone",                                      IMPACT_LOW),
    "lang":   (CAT_TECHNICAL, "Browser language",                                      IMPACT_LOW),
    "res":    (CAT_TECHNICAL, "Screen resolution",                                     IMPACT_LOW),
    "cd":     (CAT_TECHNICAL, "Screen color depth",                                    IMPACT_LOW),
    "vp":     (CAT_TECHNICAL, "Viewport size",                                         IMPACT_LOW),
    "ds":     (CAT_TECHNICAL, "Document size",                                         IMPACT_LOW),
    "cs":     (CAT_TECHNICAL, "Document character set",                                IMPACT_LOW),
    "cookie": (CAT_TECHNICAL, "Cookies-enabled flag",                                  IMPACT_LOW),
    "f_pdf":   (CAT_TECHNICAL, "PDF-plugin probe (legacy)",                            IMPACT_LOW),
    "f_qt":    (CAT_TECHNICAL, "QuickTime-plugin probe (legacy)",                      IMPACT_LOW),
    "f_realp": (CAT_TECHNICAL, "RealPlayer-plugin probe (legacy)",                     IMPACT_LOW),
    "f_wma":   (CAT_TECHNICAL, "Windows Media plugin probe (legacy)",                  IMPACT_LOW),
    "f_dir":   (CAT_TECHNICAL, "Director plugin probe (legacy)",                       IMPACT_LOW),
    "f_fla":   (CAT_TECHNICAL, "Flash plugin probe (legacy)",                          IMPACT_LOW),
    "f_java":  (CAT_TECHNICAL, "Java plugin probe (legacy)",                           IMPACT_LOW),
    "f_gears": (CAT_TECHNICAL, "Google Gears plugin probe (legacy)",                   IMPACT_LOW),
    "f_ag":    (CAT_TECHNICAL, "Silverlight plugin probe (legacy)",                    IMPACT_LOW),
}


_EVENT_FIELDS: tuple[tuple[str, str, str, str, str], ...] = (
    ("aid",  "(body) aid",  CAT_TECHNICAL,  "Application ID (per-site key)",                        IMPACT_LOW),
    ("duid", "(body) duid", CAT_IDENTIFIER, "Domain user ID (first-party cookie set client-side)",  IMPACT_HIGH),
    ("nuid", "(body) nuid", CAT_IDENTIFIER, "Network user ID (server-set persistent pseudonym)",    IMPACT_HIGH),
    ("sid",  "(body) sid",  CAT_IDENTIFIER, "Session ID",                                            IMPACT_MEDIUM),
    ("uid",  "(body) uid",  CAT_PII,        "Site-supplied user ID",                                IMPACT_HIGH),
    ("fp",   "(body) fp",   CAT_IDENTIFIER, "Browser fingerprint",                                  IMPACT_HIGH),
    ("ip",   "(body) ip",   CAT_PII,        "Client-IP override",                                   IMPACT_HIGH),
    ("url",  "(body) url",  CAT_CONTENT,    "Page URL",                                             IMPACT_MEDIUM),
)


_PII_NAME_PARTS: tuple[str, ...] = (
    "email", "mail", "phone", "tel", "address", "street", "city", "state",
    "country", "zip", "postal", "ssn", "tax", "birth", "dob",
    "username", "user_id", "userid", "firstname", "lastname", "fullname",
    "first_name", "last_name", "full_name",
)


def _looks_pii(field_name: str) -> bool:
    name = field_name.lower()
    return any(kw in name for kw in _PII_NAME_PARTS)


def _decode_self_describing(raw) -> dict | None:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        pass
    try:
        decoded = base64.b64decode(raw, validate=False).decode("utf-8")
        return json.loads(decoded)
    except (ValueError, TypeError, UnicodeDecodeError):
        return None


def _parse_tp2_body(body: str | None) -> list[ParamInfo]:
    if not body:
        return []
    envelope = _decode_self_describing(body)
    if not isinstance(envelope, dict):
        return []
    events = envelope.get("data")
    if not isinstance(events, list) or not events:
        return []

    extracted: list[ParamInfo] = [
        ParamInfo(
            key="(body) batched_event_count",
            value=str(len(events)),
            category=CAT_BEHAVIORAL,
            meaning="Number of events shipped in this tp2 POST batch",
            privacy_impact=IMPACT_MEDIUM,
            event_index=0,
        ),
    ]

    types_seen = sorted({
        str(ev.get("e", "?"))
        for ev in events
        if isinstance(ev, dict) and ev.get("e")
    })
    if types_seen:
        extracted.append(ParamInfo(
            key="(body) event_types",
            value=", ".join(types_seen),
            category=CAT_BEHAVIORAL,
            meaning="Distinct event-type codes in this batch (pv=page-view, pp=page-ping, se=structured, ue=unstructured, tr=transaction, ti=transaction-item, ad=ad)",
            privacy_impact=IMPACT_MEDIUM,
            event_index=0,
        ))

    first = events[0] if isinstance(events[0], dict) else None
    if first is None:
        return extracted

    for json_key, label, category, meaning, impact in _EVENT_FIELDS:
        value = first.get(json_key)
        if value:
            extracted.append(ParamInfo(
                key=label, value=str(value),
                category=category, meaning=meaning,
                privacy_impact=impact, event_index=0,
            ))

    extracted.extend(_parse_contexts(first.get("co") or first.get("cx")))
    extracted.extend(_parse_unstruct(first.get("ue_pr") or first.get("ue_px")))

    return extracted


def _parse_contexts(raw) -> list[ParamInfo]:
    if raw is None or raw == "":
        return []
    decoded = _decode_self_describing(raw)
    if not isinstance(decoded, dict):
        return []
    entities = decoded.get("data")
    if not isinstance(entities, list) or not entities:
        return []

    out: list[ParamInfo] = [
        ParamInfo(
            key="(body) co count",
            value=str(len(entities)),
            category=CAT_BEHAVIORAL,
            meaning="Number of custom-context entities attached to this event",
            privacy_impact=IMPACT_MEDIUM,
            event_index=0,
        )
    ]
    for idx, entity in enumerate(entities[:5], start=1):
        if not isinstance(entity, dict):
            continue
        schema = entity.get("schema")
        if schema:
            out.append(ParamInfo(
                key=f"(body) co #{idx} schema",
                value=str(schema)[:120],
                category=CAT_TECHNICAL,
                meaning="Iglu schema URL — describes what this context entity is (operator's choice)",
                privacy_impact=IMPACT_LOW,
                event_index=0,
            ))
        data = entity.get("data")
        if isinstance(data, dict) and data:
            keys = sorted(data.keys())
            has_pii = any(_looks_pii(k) for k in keys)
            preview = ", ".join(keys[:8]) + ("…" if len(keys) > 8 else "")
            out.append(ParamInfo(
                key=f"(body) co #{idx} fields",
                value=preview,
                category=CAT_PII if has_pii else CAT_BEHAVIORAL,
                meaning=(
                    "Context-entity field names — name-shape suggests PII content"
                    if has_pii else
                    "Context-entity field names (values not surfaced)"
                ),
                privacy_impact=IMPACT_HIGH if has_pii else IMPACT_MEDIUM,
                event_index=0,
            ))
    return out


def _parse_unstruct(raw) -> list[ParamInfo]:
    if raw is None or raw == "":
        return []
    decoded = _decode_self_describing(raw)
    if not isinstance(decoded, dict):
        return []
    inner = decoded.get("data")
    if not isinstance(inner, dict):
        return []

    out: list[ParamInfo] = []
    inner_schema = inner.get("schema")
    if inner_schema:
        out.append(ParamInfo(
            key="(body) ue schema",
            value=str(inner_schema)[:120],
            category=CAT_BEHAVIORAL,
            meaning="Iglu schema URL of the unstructured event (purchase / signup / share / …)",
            privacy_impact=IMPACT_MEDIUM,
            event_index=0,
        ))
    inner_data = inner.get("data")
    if isinstance(inner_data, dict) and inner_data:
        keys = sorted(inner_data.keys())
        has_pii = any(_looks_pii(k) for k in keys)
        preview = ", ".join(keys[:8]) + ("…" if len(keys) > 8 else "")
        out.append(ParamInfo(
            key="(body) ue fields",
            value=preview,
            category=CAT_PII if has_pii else CAT_BEHAVIORAL,
            meaning=(
                "Unstructured-event payload field names — name-shape suggests PII"
                if has_pii else
                "Unstructured-event payload field names (values not surfaced)"
            ),
            privacy_impact=IMPACT_HIGH if has_pii else IMPACT_MEDIUM,
            event_index=0,
        ))
    return out


@register
class SnowplowModule(TrackerModule):
    """Detect Snowplow Analytics across hosted, self-hosted, and custom deployments."""

    module_id = "snowplow"
    module_name = "Snowplow Analytics"
    vendor = "Snowplow Analytics Ltd"
    # Jurisdiction is per-instance for Snowplow — see the ``(deployment) …``
    # ParamInfo each hit carries. Class-level fields stay blank so the
    # report doesn't bucket self-hosted instances under Snowplow's UK.
    legal_jurisdiction = ""
    data_residency = ""
    sovereignty_notes = ""
    # BASE = self-hosted Snowplow (the collector runs in the operator's
    # own cloud — its defining trait): privacy 2.0 (granular pseudonymous
    # event profile, but operator-controlled — rubric privacy 2.0);
    # security 0.0 / resilience 0.0 (operator-run infrastructure).
    impact_rating = ImpactRating(privacy=2.0, security=0.0, resilience=0.0)
    impact_notes = {
        "privacy": "Builds a granular per-visitor event profile, but the "
            "collector runs in the operator's own cloud — the data stays "
            "first-party.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if any(host.endswith(suffix) for suffix in _HOSTED_SUFFIXES):
            return True
        path = urlparse(event.url).path
        if any(path.endswith(suffix) for suffix in _PATH_SUFFIXES):
            return True
        params = event.query_params
        if "tv" in params and params.get("e") in _EVENT_CODES:
            return True
        body = event.request_body
        return bool(body) and _BODY_SCHEMA_MARKER in body

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Snowplow parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key, value=value, category=category, meaning=meaning,
                    privacy_impact=impact, event_index=event.event_id,
                )
            )
        for body_param in _parse_tp2_body(event.request_body):
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

    Snowplow BDP (``*.snplow.net`` / ``*.snowplowanalytics.com``) is
    operated by Snowplow Analytics Ltd in the UK. Everything else is a
    self-hosted instance controlled by whoever runs the collector —
    the ``(infra) hosting`` ParamInfo added by the runner names that
    operator's hosting provider.
    """
    if is_hosted_snowplow_host(event.host):
        return ParamInfo(
            key="(deployment) Snowplow BDP",
            value=event.host,
            category=CAT_OTHER,
            meaning=(
                "Snowplow BDP (hosted by Snowplow Analytics Ltd, UK). "
                "Multiple regions available; UK post-Brexit data-protection "
                "regime applies."
            ),
            privacy_impact=IMPACT_MEDIUM,
            event_index=event.event_id,
        )
    return ParamInfo(
        key="(deployment) self-hosted",
        value=event.host,
        category=CAT_OTHER,
        meaning=(
            "Self-hosted Snowplow — data goes to the site operator "
            "running this collector, not to Snowplow Analytics Ltd. "
            "See the ``(infra) hosting`` ParamInfo for the actual "
            "ASN / country."
        ),
        privacy_impact=IMPACT_LOW,
        event_index=event.event_id,
    )
