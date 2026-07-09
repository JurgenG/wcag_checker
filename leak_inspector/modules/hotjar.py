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

"""Hotjar detector.

Hotjar is a session-replay and heatmap product. Acquired by
Contentsquare in 2021 — EU controller.
"""

from __future__ import annotations

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


_HOST_SUFFIXES: tuple[str, ...] = (".hotjar.com", ".hotjar.io")
_HOST_EXACT: frozenset[str] = frozenset({"hotjar.com", "hotjar.io"})


_PARAMS: dict[str, tuple[str, str, str]] = {
    "hjid":       (CAT_TECHNICAL,  "Hotjar site ID",                            IMPACT_LOW),
    "site_id":    (CAT_TECHNICAL,  "Hotjar site ID (alternate form)",           IMPACT_LOW),
    "user_id":    (CAT_IDENTIFIER, "Hotjar visitor ID (persistent pseudonym)",  IMPACT_HIGH),
    "visit_id":   (CAT_IDENTIFIER, "Visit / session ID (per-visit, not visitor-persistent — see ``user_id``)", IMPACT_MEDIUM),
    "session_id": (CAT_IDENTIFIER, "Session ID (per-session, not visitor-persistent)", IMPACT_MEDIUM),
    "recording_id": (CAT_IDENTIFIER, "Per-recording ID (one chunk of replay data)", IMPACT_MEDIUM),
    "uid":             (CAT_PII, "Site-supplied user ID (Hotjar Identify API)", IMPACT_HIGH),
    "user_attributes": (CAT_PII, "Site-supplied user attributes (custom key/value tags)", IMPACT_HIGH),
    "events":           (CAT_BEHAVIORAL, "Session-replay event chunk (mouse, scroll, DOM mutations)", IMPACT_HIGH),
    "user_interaction": (CAT_BEHAVIORAL, "Interaction event (click / scroll / input)", IMPACT_HIGH),
    "actions":          (CAT_BEHAVIORAL, "Recorded action stream",              IMPACT_HIGH),
    "heatmap_data":     (CAT_BEHAVIORAL, "Heatmap aggregation payload",         IMPACT_MEDIUM),
    "url":         (CAT_CONTENT, "Page URL the hit fired on",                   IMPACT_MEDIUM),
    "page_url":    (CAT_CONTENT, "Page URL (alternate form)",                   IMPACT_MEDIUM),
    "referrer":    (CAT_CONTENT, "Document referrer",                           IMPACT_MEDIUM),
    "page_title":  (CAT_CONTENT, "Page title",                                  IMPACT_LOW),
    "survey_id":   (CAT_TECHNICAL,  "Survey ID",                                IMPACT_LOW),
    "feedback_id": (CAT_TECHNICAL,  "Feedback-widget ID",                       IMPACT_LOW),
    "answers":     (CAT_PII, "Survey answers (often free-text PII)",            IMPACT_HIGH),
    "rating":      (CAT_BEHAVIORAL, "Feedback rating value",                    IMPACT_LOW),
    "screen_resolution": (CAT_TECHNICAL, "Screen resolution",                   IMPACT_LOW),
    "viewport_size":     (CAT_TECHNICAL, "Viewport size",                       IMPACT_LOW),
    "user_agent":        (CAT_TECHNICAL, "User-Agent string (echoed in body)",  IMPACT_LOW),
    "language":          (CAT_TECHNICAL, "Browser language",                    IMPACT_LOW),
    "platform":          (CAT_TECHNICAL, "OS / platform",                       IMPACT_LOW),
    "browser":           (CAT_TECHNICAL, "Browser identifier",                  IMPACT_LOW),
    "country":           (CAT_TECHNICAL, "Country (derived from IP server-side)", IMPACT_LOW),
    "sv":   (CAT_TECHNICAL, "Hotjar script version",                            IMPACT_LOW),
    "hjsv": (CAT_TECHNICAL, "Hotjar script version (alt key)",                  IMPACT_LOW),
    "v":    (CAT_TECHNICAL, "Hotjar protocol version",                          IMPACT_LOW),
    "r":    (CAT_TECHNICAL, "Random cache-buster",                              IMPACT_LOW),
    "ts":   (CAT_TECHNICAL, "Client-side timestamp",                            IMPACT_LOW),
    "seq":  (CAT_TECHNICAL, "Sequence number",                                  IMPACT_LOW),
    "bs":   (CAT_TECHNICAL, "Bundle / build state indicator",                   IMPACT_LOW),
    "consent":      (CAT_CONSENT, "Consent state",                              IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "TCF consent string",                         IMPACT_LOW),
}


@register
class HotjarModule(TrackerModule):
    """Detect Hotjar session-replay, heatmap, survey, and feedback traffic."""

    module_id = "hotjar"
    module_name = "Hotjar"
    vendor = "Contentsquare SAS (acquired Hotjar in 2021)"
    legal_jurisdiction = "FR"
    data_residency = "EU"
    sovereignty_notes = "EU-controlled controller; session-replay payload contains full visitor interaction"
    # privacy 4.5 / security 3.5: session replay (see Clarity) — same
    #   indiscriminate-capture + input-capturing-by-design class.
    # resilience 1.5: Contentsquare SAS is EU (France) — GDPR-native, no
    #   Schrems II — but replay has accumulated recordings/heatmaps =
    #   real switching costs (rubric resilience 1.5, EU vendor w/ lock-in).
    #   Deliberately BELOW the US replay vendors (Clarity/FullStory 2.5):
    #   the resilience axis is jurisdiction-driven, so EU Hotjar must beat
    #   them. (Conscious change from the proposal's worked-example 2.5,
    #   which misfiled an EU vendor on the high-risk-jurisdiction line.)
    impact_rating = ImpactRating(privacy=4.5, security=3.5, resilience=1.5)
    impact_notes = {
        "privacy": "Session replay records mouse, scroll and form "
            "interaction — it routinely ingests personal data the visitor "
            "types before any submit.",
        "security": "Input/DOM capture is the feature; one masking "
            "misconfiguration turns it into a PII harvester.",
        "resilience": "An EU-owned vendor (Contentsquare, France), but "
            "the accumulated recordings make it sticky to switch away.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _HOST_EXACT:
            return True
        return any(host.endswith(suffix) for suffix in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Hotjar parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key, value=value, category=category, meaning=meaning,
                    privacy_impact=impact, event_index=event.event_id,
                )
            )
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
