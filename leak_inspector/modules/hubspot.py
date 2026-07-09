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

"""HubSpot detector (CRM tracking + forms + ads).

HubSpot bundles behaviour tracking (visitor pseudonym ``hubspotutk``),
form submissions (passive listener on every ``<form>`` shipping field
values to ``forms.hubspot.com/uploads/form/v2/<portal>/<form>``), and
ad pixel mirroring via ``hsadspixel.net``.
"""

from __future__ import annotations

import json
from urllib.parse import unquote_plus

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


_HOST_SUFFIXES: tuple[str, ...] = (
    ".hubspot.com",
    ".hs-scripts.com",
    ".hs-analytics.net",
    ".hs-banner.com",
    ".hsforms.net",
    ".hsforms.com",
    ".hsadspixel.net",
    ".hubspotusercontent.com",
    ".hubspotusercontent-na1.net",
    ".hubspotusercontent-eu1.net",
)
_HOST_EXACT: frozenset[str] = frozenset({
    "hubspot.com",
    "hs-scripts.com",
    "hs-analytics.net",
    "hs-banner.com",
    "hsforms.net",
    "hsforms.com",
    "hsadspixel.net",
})


_PARAMS: dict[str, tuple[str, str, str]] = {
    "hubspotutk":  (CAT_IDENTIFIER, "Persistent visitor pseudonym (``hubspotutk`` cookie)", IMPACT_HIGH),
    "__hstc":      (CAT_IDENTIFIER, "Tracking-cookie value (visitor + session timestamps)", IMPACT_HIGH),
    "__hssc":      (CAT_IDENTIFIER, "Session cookie value (per-session, not visitor-persistent — see ``hubspotutk``)", IMPACT_MEDIUM),
    "__hsfp":      (CAT_IDENTIFIER, "Visitor fingerprint",                      IMPACT_HIGH),
    "__hssrc":     (CAT_IDENTIFIER, "Cross-domain tracking source ID",          IMPACT_MEDIUM),
    "portalId":    (CAT_TECHNICAL,  "HubSpot portal (customer) ID",             IMPACT_LOW),
    "portalid":    (CAT_TECHNICAL,  "HubSpot portal ID (alt case)",             IMPACT_LOW),
    "formId":      (CAT_TECHNICAL,  "HubSpot form UUID",                        IMPACT_LOW),
    "formid":      (CAT_TECHNICAL,  "HubSpot form UUID (alt case)",             IMPACT_LOW),
    "guid":        (CAT_IDENTIFIER, "Form-instance GUID",                       IMPACT_MEDIUM),
    "k":           (CAT_IDENTIFIER, "Per-form correlation key",                 IMPACT_MEDIUM),
    "et":          (CAT_BEHAVIORAL, "Event type code",                          IMPACT_MEDIUM),
    "ev":          (CAT_BEHAVIORAL, "Event name",                               IMPACT_MEDIUM),
    "ct":          (CAT_TECHNICAL,  "Client timestamp",                         IMPACT_LOW),
    "n":           (CAT_TECHNICAL,  "Event sequence number",                    IMPACT_LOW),
    "sd":          (CAT_TECHNICAL,  "Screen dimensions",                        IMPACT_LOW),
    "cd":          (CAT_TECHNICAL,  "Color depth",                              IMPACT_LOW),
    "ln":          (CAT_TECHNICAL,  "Browser language",                         IMPACT_LOW),
    "tz":          (CAT_TECHNICAL,  "Timezone offset",                          IMPACT_LOW),
    "v":           (CAT_TECHNICAL,  "Pixel script version",                     IMPACT_LOW),
    "vi":          (CAT_TECHNICAL,  "Visitor identifier-context flag",          IMPACT_LOW),
    "r":           (CAT_TECHNICAL,  "Random cache-buster",                      IMPACT_LOW),
    "submissionType": (CAT_BEHAVIORAL, "Form-submission transport (xhr / iframe)", IMPACT_LOW),
    "skipValidation": (CAT_TECHNICAL,  "Validation-skip flag",                  IMPACT_LOW),
    "captchaEnabled": (CAT_TECHNICAL,  "CAPTCHA-enabled flag",                  IMPACT_LOW),
    "url":      (CAT_CONTENT, "Page URL the event fired on",                    IMPACT_MEDIUM),
    "u":        (CAT_CONTENT, "Page URL (short form)",                          IMPACT_MEDIUM),
    "referrer": (CAT_CONTENT, "Document referrer",                              IMPACT_MEDIUM),
    "ref":      (CAT_CONTENT, "Document referrer (short form)",                 IMPACT_MEDIUM),
    "pt":       (CAT_CONTENT, "Page title",                                     IMPACT_LOW),
    "title":    (CAT_CONTENT, "Page title (alt form)",                          IMPACT_LOW),
    "email":     (CAT_PII, "Visitor email — set when site has identified the user", IMPACT_HIGH),
    "firstname": (CAT_PII, "Visitor first name",                                IMPACT_HIGH),
    "lastname":  (CAT_PII, "Visitor last name",                                 IMPACT_HIGH),
    "phone":     (CAT_PII, "Visitor phone",                                     IMPACT_HIGH),
    "company":   (CAT_PII, "Visitor company / organization",                    IMPACT_MEDIUM),
    "jobtitle":  (CAT_PII, "Visitor job title",                                 IMPACT_MEDIUM),
}


_CONTEXT_FIELDS: tuple[tuple[str, str, str, str, str], ...] = (
    ("hutk",                 "(body) context.hutk",             CAT_IDENTIFIER, "HubSpot visitor pseudonym (the ``hubspotutk`` cookie value)", IMPACT_HIGH),
    ("pageUri",              "(body) context.pageUri",          CAT_CONTENT,    "URL of the page that submitted the form",                    IMPACT_MEDIUM),
    ("pageName",             "(body) context.pageName",         CAT_CONTENT,    "Title of the submitting page",                               IMPACT_LOW),
    ("ipAddress",            "(body) context.ipAddress",        CAT_PII,        "Visitor IP address (when explicitly forwarded)",             IMPACT_HIGH),
    ("sfdcCampaignId",       "(body) context.sfdcCampaignId",   CAT_TECHNICAL,  "Salesforce campaign ID attributed to the submission",        IMPACT_LOW),
    ("goToWebinarWebinarKey", "(body) context.gotoWebinarKey",   CAT_TECHNICAL,  "GoToWebinar webinar key",                                     IMPACT_LOW),
)


def _parse_form_body(
    body: str | None,
    hs_context_raw: str | None,
) -> list[ParamInfo]:
    extracted: list[ParamInfo] = []

    body_obj: dict | None = None
    if body:
        try:
            decoded = json.loads(body.strip())
        except (ValueError, TypeError):
            decoded = None
        if isinstance(decoded, dict):
            body_obj = decoded

    if body_obj is not None:
        fields = body_obj.get("fields")
        if isinstance(fields, list):
            for entry in fields:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                value = entry.get("value")
                if not name:
                    continue
                category, meaning, impact = _classify_field(str(name))
                display_value = "" if value is None else str(value)
                if len(display_value) > 120:
                    display_value = display_value[:120] + "…"
                extracted.append(ParamInfo(
                    key=f"(body) field.{name}",
                    value=display_value,
                    category=category,
                    meaning=meaning,
                    privacy_impact=impact,
                    event_index=0,
                ))
            if fields:
                extracted.append(ParamInfo(
                    key="(body) form_field_count",
                    value=str(len(fields)),
                    category=CAT_BEHAVIORAL,
                    meaning="Number of fields submitted in this form",
                    privacy_impact=IMPACT_MEDIUM,
                    event_index=0,
                ))

        context = body_obj.get("context")
        if isinstance(context, dict):
            extracted.extend(_context_params(context))

        legal = body_obj.get("legalConsentOptions")
        if isinstance(legal, dict):
            consent_branch = legal.get("consent") or legal.get("legitimateInterest")
            if isinstance(consent_branch, dict) and consent_branch.get("text"):
                preview = str(consent_branch["text"])[:120]
                extracted.append(ParamInfo(
                    key="(body) legal.consent_text",
                    value=preview + ("…" if len(consent_branch["text"]) > 120 else ""),
                    category=CAT_CONSENT,
                    meaning="Consent text the visitor was shown at submission",
                    privacy_impact=IMPACT_LOW,
                    event_index=0,
                ))

    if hs_context_raw:
        try:
            ctx = json.loads(unquote_plus(hs_context_raw))
        except (ValueError, TypeError):
            ctx = None
        if isinstance(ctx, dict):
            extracted.extend(_context_params(ctx))

    return extracted


def _context_params(context: dict) -> list[ParamInfo]:
    out: list[ParamInfo] = []
    for ctx_key, label, category, meaning, impact in _CONTEXT_FIELDS:
        value = context.get(ctx_key)
        if value:
            out.append(ParamInfo(
                key=label,
                value=str(value),
                category=category,
                meaning=meaning,
                privacy_impact=impact,
                event_index=0,
            ))
    return out


def _classify_field(name: str) -> tuple[str, str, str]:
    lower = name.lower()

    if lower in _PARAMS:
        return _PARAMS[lower]

    if lower in ("fullname", "full_name", "name"):
        return CAT_PII, f"Visitor name (field: {name!r})", IMPACT_HIGH
    if lower in ("mobile", "mobilephone", "mobile_phone", "telephone", "phonenumber"):
        return CAT_PII, f"Visitor phone (field: {name!r})", IMPACT_HIGH
    if any(kw in lower for kw in ("address", "street", "city", "state", "country", "zip", "postal")):
        return CAT_PII, f"Visitor location/address field: {name!r}", IMPACT_HIGH
    if lower in ("birthday", "birthdate", "dob", "date_of_birth"):
        return CAT_PII, "Visitor date of birth", IMPACT_HIGH
    if lower in ("ssn", "tin", "tax_id", "social_security_number"):
        return CAT_PII, "Government identifier", IMPACT_HIGH
    if lower in ("organization", "org", "employer"):
        return CAT_PII, f"Visitor organization (field: {name!r})", IMPACT_MEDIUM
    if lower in ("job_title", "title", "role", "position"):
        return CAT_PII, f"Visitor job title (field: {name!r})", IMPACT_MEDIUM
    if any(kw in lower for kw in ("comment", "message", "note", "feedback", "question", "inquiry", "description")):
        return CAT_PII, f"Free-text field (commonly contains PII): {name!r}", IMPACT_HIGH

    if lower.startswith("hs_"):
        return CAT_TECHNICAL, f"HubSpot internal field: {name!r}", IMPACT_LOW

    return CAT_BEHAVIORAL, f"Custom form field: {name!r}", IMPACT_MEDIUM


@register
class HubSpotModule(TrackerModule):
    """Detect HubSpot tracking, forms, ad-pixel, and chat traffic."""

    module_id = "hubspot"
    module_name = "HubSpot"
    vendor = "HubSpot, Inc."
    legal_jurisdiction = "US"
    data_residency = "US default; EU customers can opt into Frankfurt data center"
    sovereignty_notes = "US CLOUD Act applies regardless of EU data-center choice"
    # privacy 5.0: a passive listener ships form field values to
    #   forms.hubspot.com AND a persistent hubspotutk pseudonym joins
    #   behaviour across the visit — identified-person data out, on top of
    #   cross-site tracking (rubric privacy 5.0). security 2.5: unpinned
    #   tracking/forms snippet (rubric 2.5). resilience 3.0: a US CRM
    #   platform as the operator's marketing/measurement layer (rubric 3.0).
    impact_rating = ImpactRating(privacy=5.0, security=2.5, resilience=3.0)
    impact_notes = {
        "privacy": "A passive listener ships form field values to HubSpot "
            "and a persistent hubspotutk joins behaviour across the "
            "visit — identified-person data leaves the site.",
        "security": "Loads an unpinned tracking/forms snippet into your "
            "origin.",
        "resilience": "A US CRM as the operator's marketing/measurement "
            "layer — operational dependence on a foreign platform.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _HOST_EXACT:
            return True
        return any(host.endswith(suffix) for suffix in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        hs_context_raw: str | None = None
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized HubSpot parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key, value=value, category=category, meaning=meaning,
                    privacy_impact=impact, event_index=event.event_id,
                )
            )
            if key == "hs_context":
                hs_context_raw = value
        for body_param in _parse_form_body(event.request_body, hs_context_raw):
            body_param.event_index = event.event_id
            params.append(body_param)
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
