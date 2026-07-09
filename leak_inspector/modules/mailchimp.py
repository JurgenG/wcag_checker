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

"""Mailchimp detector.

Mailchimp embeds popup / embedded signup forms (JS widget from
``chimpstatic.com``) that POST the visitor's email + custom fields to
``*.list-manage.com/subscribe/post``. The subscribe-post endpoint is the
form-leakage smoking gun — same role as HubSpot's
``forms.hubspot.com/uploads/form/v2/...``.
"""

from __future__ import annotations

import json
import re

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


_MERGE_NAME_RE = re.compile(r"^MMERGE(\d+)$")

_GROUP_RE = re.compile(r"^group\[(\d+)\](?:\[(\d+)\])?$")

_HONEYPOT_RE = re.compile(r"^b_[0-9a-fA-F]+_[0-9a-fA-F]+$")


_HOST_SUFFIXES: tuple[str, ...] = (
    ".list-manage.com",
    ".mailchimp.com",
    ".chimpstatic.com",
)
_HOST_EXACT: frozenset[str] = frozenset({
    "list-manage.com",
    "mailchimp.com",
    "chimpstatic.com",
})


_PARAMS: dict[str, tuple[str, str, str]] = {
    "u":      (CAT_TECHNICAL,  "Mailchimp account / user-hash identifier",      IMPACT_LOW),
    "id":     (CAT_TECHNICAL,  "Mailchimp list ID",                             IMPACT_LOW),
    "f_id":   (CAT_TECHNICAL,  "Mailchimp embedded-form ID",                    IMPACT_LOW),
    "uniqid": (CAT_IDENTIFIER, "Per-subscription unique ID",                    IMPACT_MEDIUM),
    "e":      (CAT_IDENTIFIER, "Subscriber email-hash identifier (open-tracking)", IMPACT_HIGH),
    "EMAIL":     (CAT_PII, "Subscriber email — submitted via embedded form",   IMPACT_HIGH),
    "FNAME":     (CAT_PII, "Subscriber first name",                            IMPACT_HIGH),
    "LNAME":     (CAT_PII, "Subscriber last name",                             IMPACT_HIGH),
    "PHONE":     (CAT_PII, "Subscriber phone",                                 IMPACT_HIGH),
    "BIRTHDAY":  (CAT_PII, "Subscriber birthday",                              IMPACT_HIGH),
    "MMERGE":    (CAT_PII, "Custom merge-field value",                         IMPACT_HIGH),
    "tags":      (CAT_BEHAVIORAL, "Subscriber-tag assignment",                  IMPACT_MEDIUM),
    "group":     (CAT_BEHAVIORAL, "Subscriber-group assignment",                IMPACT_MEDIUM),
    "referrer": (CAT_CONTENT, "Document referrer",                              IMPACT_MEDIUM),
    "c":     (CAT_TECHNICAL, "JSONP callback name",                             IMPACT_LOW),
    "v":     (CAT_TECHNICAL, "Widget version",                                  IMPACT_LOW),
}


def _classify(key: str) -> tuple[str, str, str]:
    if key in _PARAMS:
        return _PARAMS[key]

    match = _MERGE_NAME_RE.match(key)
    if match:
        return (
            CAT_PII,
            f"Custom merge field #{match.group(1)} (audience-defined, commonly PII)",
            IMPACT_HIGH,
        )

    match = _GROUP_RE.match(key)
    if match:
        gid, choice = match.group(1), match.group(2)
        if choice:
            label = f"interest group #{gid} option #{choice}"
        else:
            label = f"interest group #{gid}"
        return (
            CAT_BEHAVIORAL,
            f"Subscriber {label} selection",
            IMPACT_MEDIUM,
        )

    if _HONEYPOT_RE.match(key):
        return (
            CAT_TECHNICAL,
            "Anti-bot honeypot field (always empty for real users)",
            IMPACT_LOW,
        )

    return CAT_OTHER, "Unrecognized Mailchimp parameter", IMPACT_LOW


_V3_FIELDS: tuple[tuple[str, str, str, str, str], ...] = (
    ("email_address", "(body) email_address", CAT_PII,
     "Subscriber email (v3 list-member body)", IMPACT_HIGH),
    ("email_type",    "(body) email_type",    CAT_TECHNICAL,
     "Subscriber email format preference (html / text)", IMPACT_LOW),
    ("status",        "(body) status",        CAT_BEHAVIORAL,
     "Subscription status (subscribed / pending / unsubscribed / cleaned)", IMPACT_LOW),
    ("language",      "(body) language",      CAT_TECHNICAL,
     "Subscriber language preference", IMPACT_LOW),
    ("ip_signup",     "(body) ip_signup",     CAT_PII,
     "Visitor IP recorded at signup", IMPACT_HIGH),
    ("ip_opt",        "(body) ip_opt",        CAT_PII,
     "Visitor IP recorded at double opt-in confirm", IMPACT_HIGH),
    ("vip",           "(body) vip",           CAT_BEHAVIORAL,
     "VIP subscriber flag", IMPACT_LOW),
    ("timestamp_signup", "(body) timestamp_signup", CAT_TECHNICAL,
     "Signup timestamp", IMPACT_LOW),
    ("timestamp_opt",    "(body) timestamp_opt",    CAT_TECHNICAL,
     "Double-opt-in confirmation timestamp", IMPACT_LOW),
)


def _parse_v3_body(body: str | None) -> list[ParamInfo]:
    if not body:
        return []
    try:
        decoded = json.loads(body.strip())
    except (ValueError, TypeError):
        return []
    if not isinstance(decoded, dict) or "email_address" not in decoded:
        return []

    out: list[ParamInfo] = []

    for json_key, label, category, meaning, impact in _V3_FIELDS:
        value = decoded.get(json_key)
        if value is None or value == "":
            continue
        out.append(ParamInfo(
            key=label, value=str(value)[:120],
            category=category, meaning=meaning,
            privacy_impact=impact, event_index=0,
        ))

    merge_fields = decoded.get("merge_fields")
    if isinstance(merge_fields, dict):
        for mf_key, mf_value in merge_fields.items():
            category, meaning, impact = _classify(str(mf_key))
            if mf_value is None or mf_value == "":
                continue
            out.append(ParamInfo(
                key=f"(body) merge_fields.{mf_key}",
                value=str(mf_value)[:120],
                category=category,
                meaning=f"Merge field — {meaning}",
                privacy_impact=impact,
                event_index=0,
            ))

    interests = decoded.get("interests")
    if isinstance(interests, dict) and interests:
        selected = [gid for gid, v in interests.items() if v]
        if selected:
            preview = ", ".join(selected[:5]) + ("…" if len(selected) > 5 else "")
            out.append(ParamInfo(
                key="(body) interests",
                value=f"{len(selected)} selected: {preview}",
                category=CAT_BEHAVIORAL,
                meaning="Interest-group IDs the subscriber is opted into",
                privacy_impact=IMPACT_MEDIUM,
                event_index=0,
            ))

    tags = decoded.get("tags")
    if isinstance(tags, list) and tags:
        preview = ", ".join(str(t) for t in tags[:5]) + ("…" if len(tags) > 5 else "")
        out.append(ParamInfo(
            key="(body) tags",
            value=preview,
            category=CAT_BEHAVIORAL,
            meaning="Tags applied to the subscriber record",
            privacy_impact=IMPACT_MEDIUM,
            event_index=0,
        ))

    return out


@register
class MailchimpModule(TrackerModule):
    """Detect Mailchimp embed widget, subscribe endpoint, and list-management traffic."""

    module_id = "mailchimp"
    module_name = "Mailchimp"
    vendor = "Intuit Inc. (Mailchimp brand)"
    legal_jurisdiction = "US"
    data_residency = "US"
    sovereignty_notes = "Schrems II / US CLOUD Act apply; submitted email + name shipped to a US controller"
    # privacy 5.0: subscribe-post ships the visitor's email + name to a
    #   third-party controller — identified-person data out (rubric 5.0).
    # security 2.5: unpinned widget JS from chimpstatic.com (rubric 2.5).
    # resilience 3.0: a US controller as the operator's outreach/CRM
    #   channel — operational dependence on a foreign platform (rubric
    #   3.0). Higher than Mailjet's EU resilience 1.0.
    impact_rating = ImpactRating(privacy=5.0, security=2.5, resilience=3.0)
    impact_notes = {
        "privacy": "The subscribe form ships the visitor's email + name "
            "to a US controller — identified-person data leaves the site.",
        "security": "Loads an unpinned widget script (chimpstatic.com) "
            "into your origin.",
        "resilience": "A US CRM as the operator's outreach channel — "
            "operational dependence on a foreign platform.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _HOST_EXACT:
            return True
        return any(host.endswith(suffix) for suffix in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _classify(key)
            params.append(
                ParamInfo(
                    key=key, value=value, category=category, meaning=meaning,
                    privacy_impact=impact, event_index=event.event_id,
                )
            )
        for body_param in _parse_v3_body(event.request_body):
            body_param.event_index = event.event_id
            params.append(body_param)
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
