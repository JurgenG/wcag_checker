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

"""FullStory detector.

FullStory is a full-page session-replay product. By default the SDK
records the entire DOM-mutation stream including **form input values
as the visitor types them**, unless the operator has explicitly masked
fields with the ``fs-mask`` / ``fs-exclude`` classes or attributes.
This makes FullStory among the highest-impact form-content leakage
vectors in current use.

Recognized hosts (all FullStory-owned, all used exclusively for the
product):

* ``edge.fullstory.com`` — CDN / script delivery (``/s/fs.js``).
* ``rs.fullstory.com`` — recording ingestion (``/rec/page``,
  ``/rec/bundle``, ``/rec/event``).
* ``*.fullstory.com`` — other product subdomains (``app``, ``api``,
  ``staging`` regions).

The session-replay payload itself rides in POST bodies that v1.0
capture does not record. The presence of ``/rec/bundle`` POSTs is the
signal — that endpoint is the recorded DOM-mutation + input-event
stream being shipped to FullStory.
"""

from __future__ import annotations

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


_HOST_SUFFIX = ".fullstory.com"
_HOST_EXACT = "fullstory.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "OrgId":     (CAT_TECHNICAL,  "FullStory organization (customer) ID",       IMPACT_LOW),
    "UserId":    (CAT_IDENTIFIER, "Persistent visitor ID (FullStory cookie)",   IMPACT_HIGH),
    "SessionId": (CAT_IDENTIFIER, "Session ID (per-session, not visitor-persistent — see ``UserId``)", IMPACT_MEDIUM),
    "PageId":    (CAT_IDENTIFIER, "Per-page-load ID",                           IMPACT_MEDIUM),
    "ApiKey":    (CAT_TECHNICAL,  "Site-supplied API key",                      IMPACT_LOW),
    "Uid":       (CAT_PII,        "Site-supplied user identity (Identify API)", IMPACT_HIGH),
    "Channel":     (CAT_BEHAVIORAL, "Recording channel (e.g. ``bundle``, ``event``, ``page``)", IMPACT_MEDIUM),
    "RecordingId": (CAT_IDENTIFIER, "Per-recording ID (one replay chunk)",      IMPACT_MEDIUM),
    "EventType":   (CAT_BEHAVIORAL, "Recorded event type",                      IMPACT_MEDIUM),
    "EventStart":  (CAT_TECHNICAL, "Recording-chunk start timestamp",           IMPACT_LOW),
    "EventEnd":    (CAT_TECHNICAL, "Recording-chunk end timestamp",             IMPACT_LOW),
    "Seq":         (CAT_TECHNICAL, "Recording sequence number",                 IMPACT_LOW),
    "Now":         (CAT_TECHNICAL, "Client timestamp",                          IMPACT_LOW),
    "url":      (CAT_CONTENT, "Page URL",                                       IMPACT_MEDIUM),
    "PageUrl":  (CAT_CONTENT, "Page URL (alt form)",                            IMPACT_MEDIUM),
    "Referrer": (CAT_CONTENT, "Document referrer",                              IMPACT_MEDIUM),
    "Title":    (CAT_CONTENT, "Page title",                                     IMPACT_LOW),
    "v":      (CAT_TECHNICAL, "FullStory protocol version",                     IMPACT_LOW),
    "fs":     (CAT_TECHNICAL, "FullStory script version",                       IMPACT_LOW),
}


@register
class FullStoryModule(TrackerModule):
    """Detect FullStory session-replay, identify, and event traffic."""

    module_id = "fullstory"
    module_name = "FullStory"
    vendor = "FullStory, Inc."
    legal_jurisdiction = "US"
    data_residency = "US"
    sovereignty_notes = "US CLOUD Act applies; session-replay payload contains DOM + input events recorded from the visitor"
    # privacy 4.5 / security 3.5: session replay (see Clarity). FullStory
    #   records form input values *as typed* unless explicitly masked —
    #   the canonical input-capture-by-design case. resilience 2.5: US
    #   controller, replaceable supporting feature (rubric 2.5).
    impact_rating = ImpactRating(privacy=4.5, security=3.5, resilience=2.5)
    impact_notes = {
        "privacy": "Full-page session replay records form input values as "
            "the visitor types them unless explicitly masked — among the "
            "highest form-content leakage vectors in use.",
        "security": "Hooks input events and serialises the DOM by design: "
            "a masking slip makes it a keylogger.",
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
                key, (CAT_OTHER, "Unrecognized FullStory parameter", IMPACT_LOW)
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
