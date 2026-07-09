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

"""Mailjet detector.

Mailjet's web footprint is dominated by **embedded newsletter signup
widgets**. The widget loads from ``app.mailjet.com/widget/...`` and
POSTs the visitor's email (plus any custom fields) to a Mailjet
contact-list endpoint when the form is submitted — same form-leakage
class as Mailchimp's ``list-manage`` subscribe-post.

Recognized hosts (all Mailjet-owned, all used for the product):

* ``*.mailjet.com`` — primary product + widget delivery + API.
* ``*.mjt.lu`` — Mailjet's short-URL / click-tracking domain.
* ``*.mailjet.net`` — alternative ingress.

The actual submitted email + field values travel in POST bodies that
v1.0 capture does not record. The *presence* of a request to the
widget submit endpoint is the signal that an email address has left
the browser.
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


_HOST_SUFFIXES: tuple[str, ...] = (
    ".mailjet.com",
    ".mjt.lu",
    ".mailjet.net",
)
_HOST_EXACT: frozenset[str] = frozenset({
    "mailjet.com",
    "mjt.lu",
    "mailjet.net",
})


_PARAMS: dict[str, tuple[str, str, str]] = {
    "widget":    (CAT_TECHNICAL,  "Mailjet widget UUID",                        IMPACT_LOW),
    "wid":       (CAT_TECHNICAL,  "Widget ID (short form)",                     IMPACT_LOW),
    "listid":    (CAT_TECHNICAL,  "Contact-list ID",                            IMPACT_LOW),
    "contactid": (CAT_IDENTIFIER, "Per-contact ID (open / click tracking)",     IMPACT_HIGH),
    "userid":    (CAT_TECHNICAL,  "Mailjet account ID",                         IMPACT_LOW),
    "campaign":  (CAT_TECHNICAL,  "Campaign ID (open / click tracking)",        IMPACT_LOW),
    "email":     (CAT_PII, "Subscriber email — submitted via widget",          IMPACT_HIGH),
    "firstname": (CAT_PII, "Subscriber first name",                            IMPACT_HIGH),
    "lastname":  (CAT_PII, "Subscriber last name",                             IMPACT_HIGH),
    "name":      (CAT_PII, "Subscriber name",                                  IMPACT_HIGH),
    "phone":     (CAT_PII, "Subscriber phone",                                 IMPACT_HIGH),
    "company":   (CAT_PII, "Subscriber company",                               IMPACT_MEDIUM),
    "language":  (CAT_TECHNICAL, "Subscriber language preference",              IMPACT_LOW),
    "type":      (CAT_BEHAVIORAL, "Tracking-event type (open / click / unsubscribe)", IMPACT_MEDIUM),
    "url":       (CAT_CONTENT,    "Click-tracking destination URL",            IMPACT_MEDIUM),
    "v":         (CAT_TECHNICAL, "Widget / API version",                        IMPACT_LOW),
    "callback":  (CAT_TECHNICAL, "JSONP callback name",                         IMPACT_LOW),
    "r":         (CAT_TECHNICAL, "Random cache-buster",                         IMPACT_LOW),
}


@register
class MailjetModule(TrackerModule):
    """Detect Mailjet widget, subscribe, and click/open-tracking traffic."""

    module_id = "mailjet"
    module_name = "Mailjet"
    vendor = "Sinch AB (Mailjet brand)"
    legal_jurisdiction = "SE"
    data_residency = "EU (originally French; EU infrastructure preserved under Sinch)"
    sovereignty_notes = ""
    # privacy 5.0: the newsletter widget POSTs the visitor's *email* (+
    #   custom fields) to a third-party controller — identified-person
    #   data ships out (rubric privacy 5.0). The PII transfer dominates;
    #   it only fires when a form is actually submitted. security 2.5:
    #   the widget JS runs unpinned in the origin (rubric 2.5). resilience
    #   1.0: independent EU vendor (Sinch AB, SE), GDPR-native (rubric 1.0).
    impact_rating = ImpactRating(privacy=5.0, security=2.5, resilience=1.0)
    impact_notes = {
        "privacy": "The newsletter widget POSTs the visitor's email (and "
            "any fields) to a third-party controller — identified-person "
            "data leaves the site.",
        "security": "Loads an unpinned widget script into your origin.",
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
                key, (CAT_OTHER, "Unrecognized Mailjet parameter", IMPACT_LOW)
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
