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

"""Zendesk Web Widget + Chat detector.

Zendesk's web widget (the embedded help-center + chat tray on customer
sites) is the same product class as Intercom / Drift — chat plus a
visitor-tracking pixel. When a visitor opens a chat or submits a help
ticket, the *content* of the conversation leaves the browser to
Zendesk.

Recognized hosts:

* ``static.zdassets.com`` — asset CDN for the widget bundle
  (``/ekr/snippet.js``, ``/web_widget/classic/...``).
* ``ekr.zdassets.com`` — embeddable knowledge / resources config
  (``/compose/<account-uuid>``).
* ``<subdomain>.zendesk.com`` — customer's Zendesk org subdomain
  (``/embeddable/config``, ``/api/v2/help_center/...``,
  ``/frontendevents/dl``). The subdomain itself reveals the customer
  account.
* ``*.zopim.com`` — legacy Zendesk Chat (formerly Zopim) backend
  preserved for older deployments.

Conversation contents travel over WebSocket frames that v1.0 capture
does not record; user-identity fields (``name``, ``email``, ``phone``)
appear on the wire when the embedding site calls
``zE('webWidget', 'identify', {…})``.
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


_HOST_SUFFIX_ASSETS = ".zdassets.com"
_HOST_SUFFIX_ZENDESK = ".zendesk.com"
_HOST_SUFFIX_ZOPIM = ".zopim.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "key":         (CAT_TECHNICAL,  "Zendesk account key / embedded-widget key (per-customer)", IMPACT_LOW),
    "accountKey":  (CAT_TECHNICAL,  "Zendesk account key (alt form)",           IMPACT_LOW),
    "subdomain":   (CAT_TECHNICAL,  "Customer's Zendesk subdomain (reveals account name)", IMPACT_LOW),
    "embedKey":    (CAT_TECHNICAL,  "Embeddable-widget key",                    IMPACT_LOW),
    "embed":       (CAT_TECHNICAL,  "Embed identifier",                         IMPACT_LOW),
    "name":        (CAT_PII, "Visitor name (set by ``zE('webWidget', 'identify', ...)``)", IMPACT_HIGH),
    "email":       (CAT_PII, "Visitor email (set by Identify call)",            IMPACT_HIGH),
    "phone":       (CAT_PII, "Visitor phone (set by Identify call)",            IMPACT_HIGH),
    "external_id": (CAT_PII, "Site-supplied external user ID",                  IMPACT_HIGH),
    "msg":         (CAT_PII, "Chat-message content (visitor or agent)",         IMPACT_HIGH),
    "subject":     (CAT_PII, "Help-ticket subject (free text)",                 IMPACT_HIGH),
    "description": (CAT_PII, "Help-ticket body (free text — frequently sensitive)", IMPACT_HIGH),
    "event":       (CAT_BEHAVIORAL, "Widget event type (opened, closed, …)",    IMPACT_MEDIUM),
    "action":      (CAT_BEHAVIORAL, "Widget action",                            IMPACT_MEDIUM),
    "rating":      (CAT_BEHAVIORAL, "Visitor satisfaction rating",              IMPACT_LOW),
    "url":         (CAT_CONTENT, "Page URL the widget is embedded on",          IMPACT_MEDIUM),
    "referrer":    (CAT_CONTENT, "Document referrer",                           IMPACT_MEDIUM),
    "title":       (CAT_CONTENT, "Page title",                                  IMPACT_LOW),
    "widgetVersion": (CAT_TECHNICAL, "Widget bundle version",                   IMPACT_LOW),
    "version":       (CAT_TECHNICAL, "Widget version (alt form)",               IMPACT_LOW),
    "locale":        (CAT_TECHNICAL, "Widget UI locale",                        IMPACT_LOW),
    "channel":       (CAT_TECHNICAL, "Conversation channel (web / messenger)",  IMPACT_LOW),
    "type":          (CAT_TECHNICAL, "Widget config request type",              IMPACT_LOW),
}


@register
class ZendeskModule(TrackerModule):
    """Detect Zendesk Web Widget asset / config / chat traffic."""

    module_id = "zendesk"
    module_name = "Zendesk Widget"
    vendor = "Zendesk, Inc."
    legal_jurisdiction = "US"
    data_residency = "US default; EU data-center available for customers on certain plans"
    sovereignty_notes = "US CLOUD Act applies regardless of EU data-center choice"
    # Support/chat widget: privacy 2.5 (conversation content + a session
    #   pseudonym at a contained self-interested US vendor — rubric 2.5).
    #   security 2.5 (unpinned widget JS in the origin). resilience 2.5
    #   (US, replaceable support feature — rubric 2.5).
    impact_rating = ImpactRating(privacy=2.5, security=2.5, resilience=2.5)
    impact_notes = {
        "privacy": "A support/chat widget — conversation content and a "
            "session pseudonym at a contained US vendor.",
        "security": "Loads an unpinned widget script into your origin.",
        "resilience": "A US vendor for a replaceable support feature.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host.endswith(_HOST_SUFFIX_ASSETS):
            return True
        if host.endswith(_HOST_SUFFIX_ZOPIM):
            return True
        if host.endswith(_HOST_SUFFIX_ZENDESK):
            return True
        return False

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Zendesk parameter", IMPACT_LOW)
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
