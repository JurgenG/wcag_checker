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

"""Azure Application Insights detector.

Microsoft's Real-User-Monitoring + client-side telemetry service. The
JS SDK posts JSON-array envelopes to ``dc.services.visualstudio.com``;
each envelope contains a ``baseType`` (PageviewData, EventData,
RemoteDependencyData, MetricData, MessageData, ExceptionData) plus a
``baseData`` payload and ``tags`` carrying ``ai.session.id`` /
``ai.user.id`` / ``ai.user.authUserId`` / etc.
"""

from __future__ import annotations

import json
from collections import Counter

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


_HOST_EXACT = "dc.services.visualstudio.com"


def _parse_envelope_body(body: str) -> list[ParamInfo]:
    if not body:
        return []
    try:
        envelopes = json.loads(body)
    except (ValueError, TypeError):
        return []
    if not isinstance(envelopes, list) or not envelopes:
        return []

    params: list[ParamInfo] = [
        ParamInfo(
            key="(body) envelope_count",
            value=str(len(envelopes)),
            category=CAT_BEHAVIORAL,
            meaning="Number of telemetry envelopes shipped in this POST",
            privacy_impact=IMPACT_MEDIUM,
            event_index=0,
        )
    ]

    base_types: Counter[str] = Counter()
    for env in envelopes:
        if not isinstance(env, dict):
            continue
        data = env.get("data")
        if isinstance(data, dict):
            bt = data.get("baseType")
            if isinstance(bt, str):
                base_types[bt] += 1
    if base_types:
        params.append(ParamInfo(
            key="(body) telemetry_types",
            value=", ".join(f"{n}× {t}" for t, n in base_types.most_common()),
            category=CAT_BEHAVIORAL,
            meaning="Telemetry envelope types in this batch (PageviewData, RemoteDependencyData, EventData, MetricData, MessageData, ExceptionData, …)",
            privacy_impact=IMPACT_MEDIUM,
            event_index=0,
        ))

    first = next((e for e in envelopes if isinstance(e, dict)), None)
    if first is None:
        return params

    ikey = first.get("iKey")
    if isinstance(ikey, str) and ikey:
        params.append(ParamInfo(
            key="(body) iKey",
            value=ikey,
            category=CAT_TECHNICAL,
            meaning="Application Insights instrumentation key (per-customer)",
            privacy_impact=IMPACT_LOW,
            event_index=0,
        ))

    tags = first.get("tags") if isinstance(first.get("tags"), dict) else {}
    _TAG_LABELS: tuple[tuple[str, str, str, str, str], ...] = (
        ("ai.session.id",        CAT_IDENTIFIER, "Application Insights session pseudonym", IMPACT_HIGH, IMPACT_HIGH),
        ("ai.user.id",           CAT_PII,        "Authenticated-user ID (set via ``setAuthenticatedUserContext``; ``undefined`` = anonymous)", IMPACT_HIGH, IMPACT_LOW),
        ("ai.user.authUserId",   CAT_PII,        "Authenticated-user ID (alt form; ``undefined`` = anonymous)", IMPACT_HIGH, IMPACT_LOW),
        ("ai.user.accountId",    CAT_PII,        "Authenticated-account ID (``undefined`` = anonymous)", IMPACT_HIGH, IMPACT_LOW),
        ("ai.operation.id",      CAT_IDENTIFIER, "Per-operation correlation ID (per-pageload, not visitor-stable)", IMPACT_LOW, IMPACT_LOW),
        ("ai.operation.name",    CAT_CONTENT,    "Operation name — typically the page URL path",  IMPACT_MEDIUM, IMPACT_MEDIUM),
        ("ai.internal.sdkVersion", CAT_TECHNICAL, "App Insights SDK version (e.g. ``javascript:2.8.11``)", IMPACT_LOW, IMPACT_LOW),
        ("ai.internal.snippet",  CAT_TECHNICAL, "App Insights snippet version",                 IMPACT_LOW, IMPACT_LOW),
        ("ai.device.type",       CAT_TECHNICAL, "Device type (``Browser`` for the JS SDK)",     IMPACT_LOW, IMPACT_LOW),
        ("ai.device.id",         CAT_TECHNICAL, "Device identifier (string ``browser`` for the JS SDK; real device IDs only on native SDKs)", IMPACT_LOW, IMPACT_LOW),
    )
    for tag_key, cat, meaning, populated_impact, unpopulated_impact in _TAG_LABELS:
        value = tags.get(tag_key)
        if value is None or value == "":
            continue
        impact = unpopulated_impact if str(value) == "undefined" else populated_impact
        params.append(ParamInfo(
            key=f"(body) {tag_key}",
            value=str(value),
            category=cat,
            meaning=meaning,
            privacy_impact=impact,
            event_index=0,
        ))

    pv_urls: list[str] = []
    dep_targets: Counter[str] = Counter()
    event_names: Counter[str] = Counter()
    for env in envelopes:
        if not isinstance(env, dict):
            continue
        data = env.get("data")
        if not isinstance(data, dict):
            continue
        bd = data.get("baseData") if isinstance(data.get("baseData"), dict) else {}
        bt = data.get("baseType")
        if bt == "PageviewData":
            url = bd.get("url")
            if isinstance(url, str) and url and url not in pv_urls:
                pv_urls.append(url)
        elif bt == "RemoteDependencyData":
            target = bd.get("target")
            if isinstance(target, str) and target:
                dep_targets[target] += 1
        elif bt == "EventData":
            name = bd.get("name")
            if isinstance(name, str) and name:
                event_names[name] += 1

    if pv_urls:
        params.append(ParamInfo(
            key="(body) PageviewData.url",
            value="; ".join(pv_urls[:5]) + ("…" if len(pv_urls) > 5 else ""),
            category=CAT_CONTENT,
            meaning="Page URL(s) shipped as PageviewData",
            privacy_impact=IMPACT_MEDIUM,
            event_index=0,
        ))
    if dep_targets:
        top = ", ".join(f"{n}×{t}" for t, n in dep_targets.most_common(8))
        params.append(ParamInfo(
            key="(body) RemoteDependencyData.target",
            value=top + (", …" if len(dep_targets) > 8 else ""),
            category=CAT_CONTENT,
            meaning="Outbound hosts the page's JavaScript called — App Insights records the third-party network activity",
            privacy_impact=IMPACT_HIGH,
            event_index=0,
        ))
    if event_names:
        top = ", ".join(f"{n}×{name}" for name, n in event_names.most_common(8))
        params.append(ParamInfo(
            key="(body) EventData.name",
            value=top + (", …" if len(event_names) > 8 else ""),
            category=CAT_BEHAVIORAL,
            meaning="Custom event names fired by the site",
            privacy_impact=IMPACT_MEDIUM,
            event_index=0,
        ))

    return params


@register
class AzureApplicationInsightsModule(TrackerModule):
    """Detect Azure Application Insights JavaScript-SDK telemetry."""

    module_id = "azure_application_insights"
    module_name = "Azure Application Insights"
    vendor = "Microsoft Corporation"
    legal_jurisdiction = "US"
    data_residency = "Microsoft Azure (ingest region depends on App Insights resource configuration; the legacy ``dc.services.visualstudio.com`` endpoint routes to US-based collectors)"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # RUM/observability: privacy 1.5 (technical telemetry, session-tied;
    #   rubric 1.5). security 2.5 (unpinned SDK in origin). resilience 2.5
    #   (US Microsoft/Azure — a foreign observability dependency on the
    #   operator's own ops, rubric 2.5).
    impact_rating = ImpactRating(privacy=1.5, security=2.5, resilience=2.5)
    impact_notes = {
        "privacy": "Real-user monitoring telemetry tied to the session at "
            "most — no durable visitor profile.",
        "security": "Loads an unpinned SDK into your origin.",
        "resilience": "A US (Microsoft/Azure) observability dependency on "
            "the operator's own ops data.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return event.host.lower() == _HOST_EXACT

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for body_param in _parse_envelope_body(event.request_body):
            body_param.event_index = event.event_id
            params.append(body_param)
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
