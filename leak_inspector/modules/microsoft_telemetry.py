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

"""Microsoft 1DS / Aria client-telemetry detector.

Microsoft's unified client-telemetry pipeline (internally "1DS" — One
Data Strategy, formerly "Aria"). Embedded Microsoft products (Bookings,
Forms, Outlook-on-the-web, …) ship usage and performance telemetry to it
from the browser via the ``1DS-Web-JS`` / ``AWT-Web`` SDKs.

Recognised collector hosts (regional subdomains fold into the suffix):

* ``*.events.data.microsoft.com`` — the **1DS OneCollector** endpoint
  (``POST /OneCollector/1.0/``), e.g. ``eu-office`` / ``eu-mobile``.
* ``*.pipe.aria.microsoft.com`` — the legacy **Aria collector**
  (``POST /Collector/3.0/``), e.g. ``eu.pipe.aria.microsoft.com``.

Privacy story: the payloads are product telemetry (event names like
``Office.Forms.Web.Perf.Endpoint.ResponsePage``, an instrumentation
``iKey`` and the SDK version) tied at most to the session — not a
durable cross-site visitor profile. The collector is a beacon sink, not
an in-origin script (the SDK itself loads from :mod:`.microsoft_onecdn`),
but the data still leaves for a US controller.
"""

from __future__ import annotations

import json

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIXES: tuple[str, ...] = (
    ".events.data.microsoft.com",
    ".pipe.aria.microsoft.com",
)


#: Query-string fields on the collector URL. All are transport plumbing
#: or the operator's per-tenant telemetry key — none carry visitor data.
_PARAMS: dict[str, tuple[str, str, str]] = {
    "x-apikey":     (CAT_TECHNICAL, "Aria/1DS tenant telemetry key (identifies the Microsoft app/tenant, not the visitor)", IMPACT_LOW),
    "client-id":    (CAT_TECHNICAL, "Collector client mode (e.g. ``NO_AUTH``)", IMPACT_LOW),
    "sdk-version":  (CAT_TECHNICAL, "Telemetry SDK version (e.g. ``AWT-Web-CJS-1.2.0``)", IMPACT_LOW),
    "content-type": (CAT_TECHNICAL, "Telemetry payload encoding", IMPACT_LOW),
    "qsp":          (CAT_TECHNICAL, "Collector query-string-params flag", IMPACT_LOW),
    "cors":         (CAT_TECHNICAL, "CORS request flag", IMPACT_LOW),
    "w":            (CAT_TECHNICAL, "Collector protocol/wrapper selector", IMPACT_LOW),
}


def _parse_body(body: str | None) -> list[ParamInfo]:
    """Pull the first telemetry record's name / iKey / SDK from a body.

    OneCollector ships an ``application/x-json-stream`` body — one JSON
    object per line. The Aria collector uses ``bond-compact-binary``,
    which is not text-decodable and yields nothing here.
    """
    if not body:
        return []
    first_line = next((ln for ln in body.splitlines() if ln.strip()), "")
    try:
        record = json.loads(first_line)
    except (ValueError, TypeError):
        return []
    if not isinstance(record, dict):
        return []

    out: list[ParamInfo] = []
    name = record.get("name")
    if isinstance(name, str) and name:
        out.append(ParamInfo(
            key="(body) name",
            value=name,
            category=CAT_BEHAVIORAL,
            meaning="Telemetry event name (the Microsoft product feature reporting in)",
            privacy_impact=IMPACT_MEDIUM,
            event_index=0,
        ))
    ikey = record.get("iKey")
    if isinstance(ikey, str) and ikey:
        out.append(ParamInfo(
            key="(body) iKey",
            value=ikey,
            category=CAT_TECHNICAL,
            meaning="Instrumentation key (per Microsoft app/tenant, not the visitor)",
            privacy_impact=IMPACT_LOW,
            event_index=0,
        ))
    ext = record.get("ext")
    sdk = ext.get("sdk") if isinstance(ext, dict) else None
    sdk_ver = sdk.get("ver") if isinstance(sdk, dict) else None
    if isinstance(sdk_ver, str) and sdk_ver:
        out.append(ParamInfo(
            key="(body) ext.sdk.ver",
            value=sdk_ver,
            category=CAT_TECHNICAL,
            meaning="Telemetry SDK version (e.g. ``1DS-Web-JS-3.2.15``)",
            privacy_impact=IMPACT_LOW,
            event_index=0,
        ))
    return out


@register
class MicrosoftTelemetryModule(TrackerModule):
    """Detect Microsoft 1DS / Aria (OneCollector) client telemetry."""

    module_id = "microsoft_telemetry"
    module_name = "Microsoft Telemetry (1DS / Aria)"
    vendor = "Microsoft Corporation"
    legal_jurisdiction = "US"
    data_residency = "Microsoft telemetry pipeline; regional ingest (e.g. EU collectors) but US controller"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Client telemetry beacon for embedded Microsoft products: privacy 1.5
    #   (product usage/perf telemetry tied to the session at most — no
    #   durable visitor profile; cf. azure_application_insights 1.5).
    #   security 1.0 (a POST beacon sink — adds no in-origin executable
    #   surface; the SDK is attributed to microsoft_onecdn). resilience 2.5
    #   (a US Microsoft telemetry dependency riding along with the embedded
    #   product; cf. azure_application_insights 2.5).
    impact_rating = ImpactRating(privacy=1.5, security=1.0, resilience=2.5)
    impact_notes = {
        "privacy": "Ships product usage and performance telemetry to "
            "Microsoft, tied to the session at most — no durable visitor "
            "profile.",
        "resilience": "A US (Microsoft) telemetry pipeline that data "
            "leaves for whenever an embedded Microsoft product runs.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return any(host.endswith(s) for s in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Microsoft telemetry parameter", IMPACT_LOW)
            )
            params.append(ParamInfo(
                key=key, value=value, category=category, meaning=meaning,
                privacy_impact=impact, event_index=event.event_id,
            ))
        for body_param in _parse_body(event.request_body):
            body_param.event_index = event.event_id
            params.append(body_param)
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
