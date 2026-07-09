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

"""ID5 universal-identity detector.

ID5 Technology SA (UK, London) operates a cross-publisher
deterministic-identity service positioned as the post-third-party-
cookie graph for programmatic advertising. The ``id5`` cookie has a
**90-day** ``Max-Age`` and is the persistent key publishers and DSPs
synchronize their own visitor identifiers against. Observed host
fingerprint:

* ``id5-sync.com`` — primary endpoint family:

  - ``/c/<...>``, ``/i/<...>``, ``/s/<...>``, ``/k/<...>``,
    ``/qp/<...>`` — partner-numbered sync pixels (``.gif``). The
    path's first integer segment is the partner ID being matched.
  - ``/match`` — graph match endpoint (``publisher_user_id`` →
    ``id5id``).
  - ``/bounce`` — cookie-availability probe.
  - ``/gm/v3`` — POST graph-fetch (JSON body carries ``partner``,
    ``tml`` visited URL, ``ref``, ``cu``).
  - ``/api/config/prebid`` — Prebid module config fetch.
* ``cdn.id5-sync.com`` — JS asset CDN (``/api/1.0/id5-api.js``,
  ``/api/1.0/id5PrebidModule.js``).
* ``api.id5-sync.com`` — analytics (``/analytics/<partner>/id5-api-js``).
* ``lb.eu-1-id5-sync.com`` / ``lbs.eu-1-id5-sync.com`` — EU-region
  load-balancer endpoints (``/lb/v1``, ``/lbs/v1``).

The distinctive cookie surface is the ``3pi`` cookie — a
``|``-delimited list of ``<partner_id>#<timestamp>#<value>`` triples
ID5 accumulates as the visitor's cross-publisher map grows. This is
the graph in cookie form.

Sovereignty: post-Brexit, ID5 sits under the UK GDPR regime. The EU
currently maintains an adequacy decision for UK transfers, subject
to renewal. The substantive privacy story is the cross-publisher
deterministic identifier: a single key joining behavioural traces
across every publisher that integrates ID5, regardless of consent
state at any individual publisher.
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


#: ID5 also uses regional sibling registrables for load balancing
#: (``eu-1-id5-sync.com`` was observed; other regions likely use a
#: similar ``<region>-id5-sync.com`` pattern). Suffix-match those
#: variants — the ``id5-sync`` substring is distinctive enough that
#: a future ``us-1-id5-sync.com`` will register too.
_HOST_SUFFIXES: tuple[str, ...] = (
    ".id5-sync.com",
    "-id5-sync.com",  # catches lb.eu-1-id5-sync.com, lbs.eu-1-id5-sync.com, future regions
)
_HOST_EXACT = "id5-sync.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    # --- visitor / graph identifiers (HIGH — these ARE the cross-publisher graph) ---
    "puid":              (CAT_IDENTIFIER, "Partner user pseudonym being matched into the ID5 graph", IMPACT_HIGH),
    "id5id":             (CAT_IDENTIFIER, "The ID5 universal identifier itself (cross-publisher key)", IMPACT_HIGH),
    "publisher_user_id": (CAT_IDENTIFIER, "Publisher-supplied user ID (often a real account ID)", IMPACT_HIGH),
    "publisher_dsp_id":  (CAT_TECHNICAL,  "DSP integration identifier on the publisher side", IMPACT_LOW),
    "publisher_call_type": (CAT_TECHNICAL,  "Publisher call-type tag (e.g. ``redirect``)", IMPACT_LOW),
    "dsp_callback":      (CAT_IDENTIFIER, "DSP callback identifier", IMPACT_MEDIUM),
    # --- redirect / sync chain ---
    "publisher_redirecturl": (CAT_CONTENT, "Publisher-supplied downstream redirect target", IMPACT_MEDIUM),
    "callback":              (CAT_CONTENT, "Sync callback URL", IMPACT_MEDIUM),
    # --- consent signals ---
    "gdpr":         (CAT_CONSENT,    "GDPR applicability flag (1 = TCF v2.2 applies)", IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT,    "IAB TCF v2.2 consent string", IMPACT_LOW),
    "gpp":          (CAT_CONSENT,    "IAB Global Privacy Platform string", IMPACT_LOW),
    "gpp_sid":      (CAT_CONSENT,    "GPP section ID(s)", IMPACT_LOW),
    "us_privacy":   (CAT_CONSENT,    "IAB US Privacy (CCPA) signal", IMPACT_LOW),
    # --- technical / opaque ---
    "ttl": (CAT_TECHNICAL, "Cookie / sync TTL (may carry literal ``%%TTL%%`` placeholder)", IMPACT_LOW),
    "sd":  (CAT_TECHNICAL, "Sync direction / state flag", IMPACT_LOW),
    "o":   (CAT_TECHNICAL, "Origin / opcode flag", IMPACT_LOW),
}


#: JSON-body fields surfaced from ``/gm/v3`` and ``/api/config/prebid``.
#: Each entry: (json_path, label, category, meaning, impact).
#: ``json_path`` is the dotted key; on ``/gm/v3`` the per-request fields
#: live under ``requests[0]``, which we handle below.
_BODY_FIELDS: tuple[tuple[str, str, str, str, str], ...] = (
    ("partner", "(body) partner", CAT_TECHNICAL,
     "ID5 partner ID (the publisher's account in ID5's hierarchy)", IMPACT_LOW),
    ("tml",     "(body) tml",     CAT_CONTENT,
     "Top-level visited URL the bid is being requested from", IMPACT_MEDIUM),
    ("cu",      "(body) cu",      CAT_CONTENT,
     "Current URL (page-context bid target)", IMPACT_MEDIUM),
    ("ref",     "(body) ref",     CAT_CONTENT,
     "Document referrer", IMPACT_MEDIUM),
    ("v",       "(body) v",       CAT_TECHNICAL,
     "ID5 client SDK version", IMPACT_LOW),
    ("source",  "(body) source",  CAT_TECHNICAL,
     "Integration source (e.g. ``id5-prebid-ext-module``)", IMPACT_LOW),
    ("sourceVersion", "(body) sourceVersion", CAT_TECHNICAL,
     "Integration source version", IMPACT_LOW),
    ("cacheId", "(body) cacheId", CAT_IDENTIFIER,
     "Cache / request correlation ID", IMPACT_LOW),
    ("requestId", "(body) requestId", CAT_IDENTIFIER,
     "Request correlation ID (UUID)", IMPACT_LOW),
)


def _parse_body(body: str | None, event_id: int) -> list[ParamInfo]:
    """Surface meaningful top-level fields from an ID5 JSON body.

    ``/gm/v3`` wraps fields in ``{"requests": [{...}]}``; ``/api/config/prebid``
    nests under ``params``. We look in both shapes plus the top level.
    """
    if not body:
        return []
    try:
        decoded = json.loads(body)
    except (ValueError, TypeError):
        return []
    if not isinstance(decoded, dict):
        return []

    # Build a single merged dict of candidate fields across the shapes.
    candidates: dict = {}
    candidates.update(decoded)
    requests = decoded.get("requests")
    if isinstance(requests, list) and requests and isinstance(requests[0], dict):
        candidates.update(requests[0])
    params = decoded.get("params")
    if isinstance(params, dict):
        candidates.update(params)

    out: list[ParamInfo] = []
    for key, label, category, meaning, impact in _BODY_FIELDS:
        value = candidates.get(key)
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
    return out


@register
class ID5Module(TrackerModule):
    """Detect ID5 universal-identity (graph match + sync + Prebid module)."""

    module_id = "id5"
    module_name = "ID5"
    vendor = "ID5 Technology SA"
    legal_jurisdiction = "UK"
    data_residency = (
        "ID5-operated infrastructure (UK primary, with eu-1 regional "
        "load balancers for EU traffic)"
    )
    sovereignty_notes = (
        "ID5 Technology SA is UK-incorporated — UK GDPR applies, with "
        "the ICO as supervisory authority. Post-Brexit, transfers to "
        "the UK from the EU run under the UK adequacy decision (subject "
        "to periodic review). The substantive privacy concern is the "
        "cross-publisher deterministic identifier: a single graph key "
        "linking behavioural traces across every publisher that "
        "integrates ID5, regardless of consent state at any individual "
        "publisher. The ``3pi`` cookie carries the accumulated graph "
        "of partner-side IDs in cookie form."
    )
    # privacy 4.0: a cross-publisher persistent universal ID (90-day
    #   cookie) — the post-cookie graph key, cross-site by design.
    # security 3.0: a single-purpose ID library that distributes the key
    #   broadly, but does not redirect-chain to unenumerable auction
    #   servers the way an SSP does (rubric 3.0 broad-access, below 4.0).
    # resilience 1.5: ID5 Technology SA is UK — non-EU adequacy
    #   (rubric 1.5).
    impact_rating = ImpactRating(privacy=4.0, security=3.0, resilience=1.5)
    impact_notes = {
        "privacy": "A cross-publisher universal ID (90-day cookie) — the "
            "post-third-party-cookie graph key that links the visitor "
            "across every publisher that integrates it.",
        "security": "Distributes that shared ID broadly, though it is a "
            "single-purpose library, not an auction hub.",
        "resilience": "UK-incorporated — a non-EU adequacy jurisdiction.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host == _HOST_EXACT:
            return True
        return any(host.endswith(suffix) for suffix in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized ID5 parameter", IMPACT_LOW)
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
