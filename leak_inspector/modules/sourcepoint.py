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

"""Sourcepoint Consent Management Platform (CMP) detector.

Sourcepoint Technologies Inc. (US, New York) is one of the four major
enterprise CMP vendors — sits alongside the existing
:mod:`leak_inspector.modules.cookiebot`,
:mod:`leak_inspector.modules.onetrust`, and
:mod:`leak_inspector.modules.trustarc` detectors. Used by large
publishers (news sites, e-commerce) and known for comprehensive IAB
TCF v2 + Global Privacy Platform + USNAT/USP coverage.

Observed host fingerprint:

* ``cdn.privacy-mgmt.com`` — the entire Sourcepoint runtime ships
  from this single host. Paths fall into four families:

  - ``/wrapper/v2/...`` — wrapper API endpoints:

    * ``/wrapper/v2/meta-data`` — campaign metadata fetch
      (``accountId``, ``propertyId``, ``metadata``).
    * ``/wrapper/v2/messages`` — message variant fetch (which CMP
      banner to display).
    * ``/wrapper/v2/pv-data`` — page-view consent state POST (full
      ``granularStatus`` consent-decision body).
    * ``/wrapper/v2/choice/consent-all`` — bulk accept handler.
    * ``/wrapper/v2/choice/gdpr/<message_id>`` — per-message GDPR
      choice POST (JSON body: ``accountId`` + ``messageId`` +
      ``prtnUUID`` + ``uuid``).
  - ``/unified/...`` — runtime JS bundles
    (``wrapperMessagingWithoutDetection.js``,
    ``<version>/gdpr-tcf.<hash>.bundle.js``,
    ``<version>/usnat-uspapi.<hash>.bundle.js``).
  - ``/Notice.*``, ``/polyfills.*``, ``/index.html`` — notice UI assets.
  - ``/consent/tcfv2/vendor-list/...`` — IAB TCF vendor list fetch.

A CMP differs from an ad tracker in privacy posture: the data it
collects is the visitor's *consent decision*, not behavioural
telemetry. But that decision is still personal data — joined across
sessions via the ``consentUUID`` and per-partner ``prtnUUID`` cookies,
it builds a per-visitor consent history. Sovereignty notes reflect
the US controller status (Sourcepoint Technologies Inc.) — CLOUD Act
applies even though the data is "just consent".
"""

from __future__ import annotations

import json

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_CONSENT,
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


_HOST_SUFFIX = ".privacy-mgmt.com"
_HOST_EXACT = "privacy-mgmt.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    # --- property identifiers ---
    "accountId":   (CAT_TECHNICAL, "Sourcepoint customer / account ID", IMPACT_LOW),
    "propertyId":  (CAT_TECHNICAL, "Sourcepoint property ID (one per managed website)", IMPACT_LOW),
    "siteId":      (CAT_TECHNICAL, "Sourcepoint site ID (alternate naming on vendor-list endpoint)", IMPACT_LOW),
    "message_id":  (CAT_TECHNICAL, "CMP message variant being displayed to the visitor", IMPACT_LOW),
    # --- visitor consent identifiers (HIGH — join consent decisions across sessions) ---
    "consentUUID": (CAT_IDENTIFIER, "Per-visitor consent decision UUID — joins consent state across sessions", IMPACT_HIGH),
    "uuid":        (CAT_IDENTIFIER, "Sourcepoint per-visitor UUID", IMPACT_HIGH),
    "authId":      (CAT_IDENTIFIER, "Authenticated-user ID (logged-in visitors)", IMPACT_HIGH),
    "prtnUUID":    (CAT_IDENTIFIER, "Per-partner UUID — cross-partner linkability", IMPACT_HIGH),
    # --- channel / correlation ---
    "ch":          (CAT_IDENTIFIER, "Sourcepoint channel / session correlation tag", IMPACT_MEDIUM),
    # --- consent state (serialized) ---
    "metadata":    (CAT_CONSENT, "Serialized consent-campaign metadata (JSON: gdpr/usnat applies flags)", IMPACT_LOW),
    "body":        (CAT_CONSENT, "Serialized consent-message request body", IMPACT_LOW),
    "localState":  (CAT_CONSENT, "Serialized local consent state", IMPACT_LOW),
    "nonKeyedLocalState": (CAT_CONSENT, "Serialized non-keyed local consent state", IMPACT_LOW),
    "includeCustomVendorsRes": (CAT_CONSENT, "Include custom-vendors response flag", IMPACT_LOW),
    "withSiteActions":         (CAT_CONSENT, "Include site-actions in response flag", IMPACT_LOW),
    # --- page context ---
    "consent_origin": (CAT_CONTENT, "URL of the consent-collection page (where the banner is shown)", IMPACT_MEDIUM),
    # --- technical / opaque ---
    "env":            (CAT_TECHNICAL, "Sourcepoint runtime environment (``prod`` / ``stage``)", IMPACT_LOW),
    "scriptVersion":  (CAT_TECHNICAL, "Sourcepoint client script version", IMPACT_LOW),
    "scriptType":     (CAT_TECHNICAL, "Sourcepoint client script type (``unified``)", IMPACT_LOW),
    "hasCsp":         (CAT_TECHNICAL, "Page has a Content-Security-Policy probe", IMPACT_LOW),
    "preload_message": (CAT_TECHNICAL, "Preload-message flag", IMPACT_LOW),
    "version":        (CAT_TECHNICAL, "Sourcepoint runtime version", IMPACT_LOW),
}


#: JSON-body fields surfaced from the wrapper API POST endpoints
#: (``/wrapper/v2/pv-data``, ``/wrapper/v2/choice/...``). The
#: ``gdpr.applies`` / ``usnat.applies`` shape is normalised into
#: ``gdpr_applies`` / ``usnat_applies`` to keep the report flat.
_BODY_FIELDS: tuple[tuple[str, str, str, str, str], ...] = (
    ("accountId",  "(body) accountId",  CAT_TECHNICAL,
     "Sourcepoint customer / account ID", IMPACT_LOW),
    ("propertyId", "(body) propertyId", CAT_TECHNICAL,
     "Sourcepoint property ID", IMPACT_LOW),
    ("messageId",  "(body) messageId",  CAT_TECHNICAL,
     "CMP message variant ID", IMPACT_LOW),
    ("uuid",       "(body) uuid",       CAT_IDENTIFIER,
     "Sourcepoint per-visitor UUID — joins consent state across sessions", IMPACT_HIGH),
    ("authId",     "(body) authId",     CAT_IDENTIFIER,
     "Authenticated-user ID (logged-in visitors)", IMPACT_HIGH),
    ("prtnUUID",   "(body) prtnUUID",   CAT_IDENTIFIER,
     "Per-partner UUID — cross-partner linkability", IMPACT_HIGH),
    ("mmsDomain",  "(body) mmsDomain",  CAT_TECHNICAL,
     "CMP message-management subdomain", IMPACT_LOW),
)


def _parse_body(body: str | None, event_id: int) -> list[ParamInfo]:
    """Surface top-level + consent-shape fields from a Sourcepoint POST body."""
    if not body:
        return []
    try:
        decoded = json.loads(body)
    except (ValueError, TypeError):
        return []
    if not isinstance(decoded, dict):
        return []

    out: list[ParamInfo] = []
    for key, label, category, meaning, impact in _BODY_FIELDS:
        value = decoded.get(key)
        if value in (None, ""):
            continue
        out.append(ParamInfo(
            key=label,
            value=str(value),
            category=category,
            meaning=meaning,
            privacy_impact=impact,
            event_index=event_id,
        ))

    # GDPR / USNAT applicability + granular consent decision.
    for regime in ("gdpr", "usnat", "ccpa"):
        block = decoded.get(regime)
        if not isinstance(block, dict):
            continue
        applies = block.get("applies")
        if applies is not None:
            out.append(ParamInfo(
                key=f"(body) {regime}_applies",
                value=str(applies),
                category=CAT_CONSENT,
                meaning=f"Whether {regime.upper()} applies to this visitor",
                privacy_impact=IMPACT_LOW,
                event_index=event_id,
            ))
        consent_status = block.get("consentStatus")
        if isinstance(consent_status, dict):
            out.append(ParamInfo(
                key="(body) consentStatus",
                value=str(consent_status),
                category=CAT_CONSENT,
                meaning=(
                    "Granular consent state (rejectedAny / rejectedLI / "
                    "consentedAll / previousOptInAll / defaultConsent flags)"
                ),
                privacy_impact=IMPACT_LOW,
                event_index=event_id,
            ))

    return out


@register
class SourcepointModule(TrackerModule):
    """Detect Sourcepoint CMP wrapper / runtime / notice traffic."""

    module_id = "sourcepoint"
    module_name = "Sourcepoint CMP"
    vendor = "Sourcepoint Technologies Inc."
    legal_jurisdiction = "US"
    data_residency = (
        "Sourcepoint-operated infrastructure (US-primary; CDN serves "
        "globally via privacy-mgmt.com)"
    )
    sovereignty_notes = (
        "Sourcepoint is a Consent Management Platform — its role is "
        "collecting and signaling consent state, not behavioural "
        "telemetry. But the consent decision itself is personal data: "
        "joined across sessions via the ``consentUUID`` and per-partner "
        "``prtnUUID`` it builds a per-visitor consent history. "
        "Sourcepoint Technologies Inc. is US-incorporated — CLOUD Act "
        "and FISA 702 apply to the consent-state data even though it "
        "isn't ad-tech telemetry."
    )
    # US third-party CMP that builds a per-visitor consent history
    # (consentUUID / prtnUUID): privacy 1.5 (consent-state personal data
    #   joined across sessions, but not ad-tech telemetry — rubric 1.5).
    # security 3.0 (orchestrates/gates vendor scripts — code-loader).
    # resilience 2.5 (US — rubric 2.5).
    impact_rating = ImpactRating(privacy=1.5, security=3.0, resilience=2.5)
    impact_notes = {
        "privacy": "Builds a per-visitor consent history (consentUUID / "
            "prtnUUID) — personal data, though not ad-tech telemetry.",
        "security": "Orchestrates and gates vendor scripts — effectively "
            "a code-loader in your origin.",
        "resilience": "A US-controlled consent layer.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Sourcepoint parameter", IMPACT_LOW)
            )
            params.append(ParamInfo(
                key=key,
                value=value,
                category=category,
                meaning=meaning,
                privacy_impact=impact,
                event_index=event.event_id,
            ))
        params.extend(_parse_body(event.request_body, event.event_id))
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
