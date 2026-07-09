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

"""Oswald.ai conversational-AI chatbot widget detector.

Oswald is a Belgian conversational-AI vendor whose embeddable chat
widget is integrated by partner sites (observed on doccle.be) for
customer-support and FAQ chat flows.

Recognized hosts:

* ``widget.oswald.ai`` — widget loader. Serves the hashed JS/CSS
  bundles under ``/assets/`` and the configuration endpoints
  ``/widget`` and ``/bubble`` (the latter carries the bulk of the
  per-visit query parameters: chat token, session ID, locale, opt-in
  flags).
* ``api.oswald.ai`` — backend REST API under
  ``/api/v1/chats/<chat-uuid>/…``: ``config``, ``widget``,
  ``integrations``, ``zendeskAuth``, and an ``event/<chat-uuid>-<session>``
  POST sink for client-side telemetry.

Privacy notes:

* A per-visit ``session`` / ``sessionId`` pseudonym (also stored as the
  first-party cookie ``oswald_session_id`` on the embedding site) is
  shipped to oswald.ai with every request. It correlates all chat
  traffic for that visit.
* The ``token`` query parameter on ``/bubble`` is the per-customer
  chat UUID — a tenant identifier, not a visitor identifier.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIX = ".oswald.ai"
_HOST_EXACT = "oswald.ai"


_PARAMS: dict[str, tuple[str, str, str]] = {
    # --- identifiers ---
    "token":              (CAT_TECHNICAL,  "Oswald chat / tenant UUID (per-customer)", IMPACT_LOW),
    "session":            (CAT_IDENTIFIER, "Per-visit visitor session pseudonym (mirrors ``oswald_session_id`` cookie on the embedding site)", IMPACT_MEDIUM),
    "sessionId":          (CAT_IDENTIFIER, "Per-visit visitor session pseudonym (alt form)", IMPACT_MEDIUM),
    # --- behavioral / widget state ---
    "open":               (CAT_BEHAVIORAL, "Widget initial open state",        IMPACT_LOW),
    "feedback":           (CAT_BEHAVIORAL, "Feedback mode flag",               IMPACT_LOW),
    "startCommand":       (CAT_BEHAVIORAL, "Initial chat command",             IMPACT_LOW),
    "startCommandOnLoad": (CAT_BEHAVIORAL, "Auto-trigger initial command flag", IMPACT_LOW),
    "forceStartCommand":  (CAT_BEHAVIORAL, "Force-run initial command flag",   IMPACT_LOW),
    # --- environment / dispatch ---
    "locale":             (CAT_TECHNICAL, "Widget UI locale (e.g. ``nl``, ``fr``)", IMPACT_LOW),
    "environment":        (CAT_TECHNICAL, "Deployment environment (``production``, …)", IMPACT_LOW),
    "env":                (CAT_TECHNICAL, "Deployment environment (alt form)", IMPACT_LOW),
    "v":                  (CAT_TECHNICAL, "Widget protocol version",           IMPACT_LOW),
    "time":               (CAT_TECHNICAL, "Client wall-clock timestamp (millis, cache-buster)", IMPACT_LOW),
}


@register
class OswaldModule(TrackerModule):
    """Detect Oswald.ai chatbot widget and backend API traffic."""

    module_id = "oswald"
    module_name = "Oswald.ai"
    vendor = "Oswald NV (oswald.ai)"
    legal_jurisdiction = "BE"
    data_residency = "Belgium-headquartered vendor; backing infrastructure not documented from request inspection alone"
    sovereignty_notes = "EU member state (Belgium) — GDPR applies directly; no third-country transfer signal in observed traffic"
    # privacy 2.5: a chat widget at a contained EU vendor — conversation
    #   content + a session pseudonym held per-customer, not joined across
    #   the vendor's clients (rubric privacy 2.5). security 1.5: the widget
    #   runs in a vendor iframe/embed, sandboxed-ish (rubric 1.5).
    #   resilience 1.0: independent EU (BE) third party, GDPR-native, a
    #   replaceable support feature (rubric resilience 1.0).
    impact_rating = ImpactRating(privacy=2.5, security=1.5, resilience=1.0)
    impact_notes = {
        "privacy": "A chat widget at a contained EU vendor — conversation "
            "content and a session pseudonym held per-customer, not joined "
            "across the vendor's clients.",
        "security": "The widget runs in a vendor iframe/embed — "
            "sandboxed, not first-party-origin code.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Oswald parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key,
                    value=value,
                    category=category,
                    meaning=meaning,
                    privacy_impact=impact,
                    event_index=event.event_id,
                )
            )
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
