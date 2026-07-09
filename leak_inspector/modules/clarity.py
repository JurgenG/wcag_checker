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

"""Microsoft Clarity detector.

Clarity is a session-replay and heatmap product. Records mouse movement,
clicks, scrolling, and (with default settings) DOM mutations sufficient
to reconstruct what the visitor saw on the page.
"""

from __future__ import annotations

import json
import re
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


_ENVELOPE_FIELDS: tuple[tuple[int, str, str, str, str], ...] = (
    (0,  "(body) script_version", CAT_TECHNICAL,  "Clarity SDK version (from POST body envelope)",       IMPACT_LOW),
    (4,  "(body) project_id",     CAT_TECHNICAL,  "Clarity project ID (the operator's site key)",        IMPACT_LOW),
    (5,  "(body) user_id",        CAT_IDENTIFIER, "Persistent visitor pseudonym",                        IMPACT_HIGH),
    (6,  "(body) session_id",     CAT_IDENTIFIER, "Session ID (per-session, not visitor-persistent)",    IMPACT_MEDIUM),
    (11, "(body) page_url",       CAT_CONTENT,    "Page URL the replay was recorded on (from envelope)", IMPACT_MEDIUM),
)


def _parse_envelope(body: str | None) -> list[ParamInfo]:
    if not body:
        return []
    try:
        envelope = json.loads(body)
    except (ValueError, TypeError):
        return []
    if not isinstance(envelope, dict):
        return []

    params: list[ParamInfo] = []
    e_array = envelope.get("e")
    if isinstance(e_array, list):
        if len(e_array) > 0 and isinstance(e_array[0], str) and "." in e_array[0]:
            for index, key, category, meaning, impact in _ENVELOPE_FIELDS:
                if index >= len(e_array):
                    continue
                value = e_array[index]
                if value is None or value == "":
                    continue
                params.append(
                    ParamInfo(
                        key=key,
                        value=str(value),
                        category=category,
                        meaning=meaning,
                        privacy_impact=impact,
                        event_index=0,
                    )
                )

    a_array = envelope.get("a")
    if isinstance(a_array, list):
        params.append(
            ParamInfo(
                key="(body) action_count",
                value=str(len(a_array)),
                category=CAT_BEHAVIORAL,
                meaning=(
                    "Number of recorded actions (mouse moves, clicks, scroll, "
                    "DOM mutations, performance, …) in this replay chunk"
                ),
                privacy_impact=IMPACT_HIGH,
                event_index=0,
            )
        )
    return params


_PATH_IDENTIFIERS: tuple[tuple[re.Pattern, str, str, str, str], ...] = (
    (
        re.compile(r"^/tag/([^/?#]+)"),
        "(path) project_id",
        CAT_TECHNICAL,
        "Clarity project ID (the operator's site key) — extracted from URL path",
        IMPACT_LOW,
    ),
)


_HOST_SUFFIX = ".clarity.ms"
_HOST_EXACT = "clarity.ms"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "pid":   (CAT_TECHNICAL,  "Clarity project ID (the site's tracking key)", IMPACT_LOW),
    "uid":   (CAT_IDENTIFIER, "Persistent visitor ID",                         IMPACT_HIGH),
    "sid":   (CAT_IDENTIFIER, "Session ID (per-session, not visitor-persistent — see ``uid`` for the persistent pseudonym)", IMPACT_MEDIUM),
    "tid":   (CAT_IDENTIFIER, "Tab ID within a session",                       IMPACT_MEDIUM),
    "pn":    (CAT_IDENTIFIER, "Page number within the session",                IMPACT_LOW),
    "v":     (CAT_TECHNICAL,  "Clarity client library version",                IMPACT_LOW),
    "seq":   (CAT_TECHNICAL,  "Payload sequence number",                       IMPACT_LOW),
    "ts":    (CAT_TECHNICAL,  "Client-side timestamp",                         IMPACT_LOW),
    "upload": (CAT_BEHAVIORAL, "Session-replay payload blob",                  IMPACT_HIGH),
    "end":   (CAT_BEHAVIORAL, "Session-end signal",                            IMPACT_LOW),
    "url":   (CAT_CONTENT,    "Page URL the replay was recorded on",           IMPACT_MEDIUM),
    "ref":   (CAT_CONTENT,    "Referrer for the recorded page",                IMPACT_MEDIUM),
    "title": (CAT_CONTENT,    "Page title",                                    IMPACT_LOW),
    "insights": (CAT_TECHNICAL, "Clarity insights feature flag",                IMPACT_LOW),
}


@register
class ClarityModule(TrackerModule):
    """Detect Microsoft Clarity script and ingest traffic."""

    module_id = "clarity"
    module_name = "Microsoft Clarity"
    vendor = "Microsoft Corporation"
    legal_jurisdiction = "US"
    data_residency = "Microsoft Azure (region varies by tenant configuration)"
    sovereignty_notes = "US CLOUD Act applies regardless of Azure region"
    # privacy 4.5: session replay indiscriminately captures mouse/scroll/
    #   DOM + form interaction — routinely ingests PII before any submit
    #   (rubric privacy 4.5). security 3.5: input-capturing script by
    #   design — one masking misconfig turns it into a keylogger (rubric
    #   3.5). resilience 2.5: US controller, but replay is a replaceable
    #   supporting feature (rubric 2.5, high-risk-jurisdiction supporting).
    impact_rating = ImpactRating(privacy=4.5, security=3.5, resilience=2.5)
    impact_notes = {
        "privacy": "Session replay records the visitor's mouse, scrolling "
            "and form interaction — it routinely captures what they type, "
            "including personal data, before any submit.",
        "security": "Its feature set is keystroke/DOM capture: one masking "
            "misconfiguration turns it into a credential and PII harvester.",
        "resilience": "Replay analytics on a US vendor — a replaceable "
            "supporting feature.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Clarity parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key, value=value, category=category, meaning=meaning,
                    privacy_impact=impact, event_index=event.event_id,
                )
            )
        path = urlparse(event.url).path
        for pattern, key, category, meaning, impact in _PATH_IDENTIFIERS:
            match = pattern.match(path)
            if match:
                params.append(
                    ParamInfo(
                        key=key, value=match.group(1), category=category,
                        meaning=meaning, privacy_impact=impact,
                        event_index=event.event_id,
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
