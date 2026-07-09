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

"""Amazon Ad System (APS / DTB / TAM) detector.

Amazon's web ad exchange — Amazon Publisher Services (APS), the
Transparent Ad Marketplace (TAM), and the Direct-to-Buyer (DTB) bid
endpoints all ride under the single registrable
``amazon-adsystem.com``. Observed host fingerprint:

* ``aax-eu.amazon-adsystem.com`` — EU-region partner-sync + RTB
  (``/s/ecm3``, ``/s/dcm``, ``/s/iu3``, ``/s/v3/pr``). Sets ``ad-id``
  with **2-year** ``Expires``, ``Domain=.amazon-adsystem.com``.
* ``aax.amazon-adsystem.com`` — global ad exchange.
* ``s.amazon-adsystem.com`` — sync (``/dcm``, ``/ecm3``).
* ``c.amazon-adsystem.com`` / ``c.aps.amazon-adsystem.com`` —
  apstag.js loader CDN.
* ``config.aps.amazon-adsystem.com`` — APS publisher config
  (``/configs/<UUID|integer>``).
* ``client.aps.amazon-adsystem.com`` — ``/publisher.js`` client.
* ``web.ads.aps.amazon-adsystem.com`` — Prebid OpenRTB header bidding
  (``/e/pb/bid``), JSON body with ``imp``, ``site``, ``user``,
  ``device``, ``regs``.
* ``web-video.ads.aps.amazon-adsystem.com`` /
  ``web-banner.ads.aps.amazon-adsystem.com`` — direct-to-buyer
  bidding (``/e/dtb/bid``), JSON body with ``u``, ``pid``, ``ws``,
  ``v``, ``slots``.

The whole registrable is owned by Amazon and used exclusively for ad
infrastructure, so a single suffix match is sufficient and safe.

Sovereignty: Amazon.com Services LLC, US controller — CLOUD Act and
FISA 702 apply. Amazon joins this ad-side visitor graph to the
first-party retail graph (Amazon.com purchase history, Prime
identity, AWS auth) which is among the largest first-party identity
graphs on the web — a substantially larger downstream exposure than
a typical SSP.
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


_HOST_SUFFIX = ".amazon-adsystem.com"
_HOST_EXACT = "amazon-adsystem.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    # --- visitor / publisher identifiers ---
    "id":      (CAT_IDENTIFIER, "Amazon visitor pseudonym OR partner ID (path-dependent — the ``ad-id`` cookie value on cookie-match endpoints)", IMPACT_HIGH),
    "pid":     (CAT_TECHNICAL, "Publisher ID (APS account identifier)", IMPACT_LOW),
    "ex":      (CAT_TECHNICAL, "Partner being synced (the SSP graph edge — e.g. ``rubiconproject.com``, ``loopme.com``)", IMPACT_LOW),
    "exlist":  (CAT_TECHNICAL, "Underscore-delimited list of partners (graph topology)", IMPACT_LOW),
    "adunitid": (CAT_TECHNICAL, "Ad slot / unit identifier", IMPACT_LOW),
    # --- page context ---
    "d":      (CAT_CONTENT, "Domain / publisher tag (e.g. ``dtb-pub``)", IMPACT_LOW),
    "dl":     (CAT_CONTENT, "Downlink / source URL", IMPACT_MEDIUM),
    "redir":  (CAT_CONTENT, "Downstream redirect target", IMPACT_MEDIUM),
    # --- consent ---
    "gdpr":         (CAT_CONSENT, "GDPR applicability flag", IMPACT_LOW),
    "gdpr_consent": (CAT_CONSENT, "IAB TCF v2.2 consent string", IMPACT_LOW),
    "gpp":          (CAT_CONSENT, "IAB Global Privacy Platform string", IMPACT_LOW),
    "gpp_sid":      (CAT_CONSENT, "GPP section ID(s)", IMPACT_LOW),
    "us_privacy":   (CAT_CONSENT, "IAB US Privacy (CCPA) signal", IMPACT_LOW),
    # --- technical / opaque internals ---
    "cm3ppd":     (CAT_TECHNICAL, "Cookie-match v3 partner-pixel-data flag", IMPACT_LOW),
    "dcc":        (CAT_TECHNICAL, "Display cookie context flag", IMPACT_LOW),
    "csif":       (CAT_TECHNICAL, "Cross-site iframe support probe", IMPACT_LOW),
    "dmt":        (CAT_TECHNICAL, "Demand match-type flag", IMPACT_LOW),
    "status":     (CAT_TECHNICAL, "Sync status code (e.g. ``ok``)", IMPACT_LOW),
    "fv":         (CAT_TECHNICAL, "Frame visibility flag", IMPACT_LOW),
    "a":          (CAT_TECHNICAL, "Opaque Amazon internal flag", IMPACT_LOW),
    "tc":         (CAT_TECHNICAL, "Transaction / context code", IMPACT_LOW),
    "pi":         (CAT_TECHNICAL, "Opaque Amazon internal flag", IMPACT_LOW),
    "is_secure":  (CAT_TECHNICAL, "Secure-context probe", IMPACT_LOW),
    "expiration": (CAT_TECHNICAL, "Sync cache expiration", IMPACT_LOW),
}


#: Top-level JSON-body fields surfaced by ``_parse_body``. Each entry:
#: (json_key, label, category, meaning, impact).
_BODY_FIELDS: tuple[tuple[str, str, str, str, str], ...] = (
    ("u",   "(body) u",   CAT_CONTENT,
     "Visited-page URL the bid request fires on", IMPACT_MEDIUM),
    ("pid", "(body) pid", CAT_TECHNICAL,
     "Publisher ID (APS publisher slot)", IMPACT_LOW),
    ("src", "(body) src", CAT_TECHNICAL,
     "Source / account identifier", IMPACT_LOW),
    ("ws",  "(body) ws",  CAT_TECHNICAL,
     "Window / viewport size (WxH)", IMPACT_LOW),
    ("v",   "(body) v",   CAT_TECHNICAL,
     "Amazon ad SDK version", IMPACT_LOW),
    ("cb",  "(body) cb",  CAT_TECHNICAL,
     "Cache-buster (sequence number)", IMPACT_LOW),
    ("t",   "(body) t",   CAT_TECHNICAL,
     "Bid timeout (ms)", IMPACT_LOW),
)


#: Array-typed body fields surfaced as ``<label>_count``. Counting
#: rather than enumerating keeps the report concise — the granular
#: per-impression detail lives in the captured raw body.
_BODY_ARRAY_COUNTS: tuple[tuple[str, str, str], ...] = (
    ("imp",   "(body) imp_count",
     "Number of impression slots in this OpenRTB request"),
    ("slots", "(body) slots_count",
     "Number of ad slots in this DTB bid request"),
)


def _parse_body(body: str | None, event_id: int) -> list[ParamInfo]:
    """Surface meaningful top-level fields from an Amazon JSON bid body."""
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
    for key, label, meaning in _BODY_ARRAY_COUNTS:
        value = decoded.get(key)
        if isinstance(value, list):
            out.append(ParamInfo(
                key=label,
                value=str(len(value)),
                category=CAT_TECHNICAL,
                meaning=meaning,
                privacy_impact=IMPACT_LOW,
                event_index=event_id,
            ))
    return out


@register
class AmazonAdSystemModule(TrackerModule):
    """Detect Amazon Ad System (APS / DTB / TAM) requests."""

    module_id = "amazon_ad_system"
    module_name = "Amazon Ad System (APS / DTB)"
    vendor = "Amazon.com Services LLC"
    legal_jurisdiction = "US"
    data_residency = (
        "Amazon-operated infrastructure (AWS, primary US-region, "
        "regional ingest including ``aax-eu`` for EU traffic)"
    )
    sovereignty_notes = (
        "US controller — CLOUD Act and FISA 702 apply. Amazon Ad "
        "System joins its ad-side visitor graph (the ``ad-id`` 2-year "
        "cookie) to Amazon's first-party retail / Prime / AWS "
        "identity graph — among the largest first-party identity "
        "graphs on the web. The downstream exposure is materially "
        "larger than a typical SSP."
    )
    # Ad exchange (APS/TAM): privacy 4.0 (cross-site ad profile via the
    #   2-year ad-id cookie, joined to Amazon's identity graph — cross-site
    #   by design; the retail-identity join is server-side, so 4.0 not 5.0
    #   per certainty). security 4.0 (header-bidding + sync chain to
    #   unenumerable demand — rubric 4.0). resilience 2.5 (US, replaceable
    #   ad slot — rubric 2.5).
    impact_rating = ImpactRating(privacy=4.0, security=4.0, resilience=2.5)
    impact_notes = {
        "privacy": "An ad exchange joining this visit (via the 2-year "
            "ad-id cookie) to Amazon's web-wide profile — cross-site by "
            "design.",
        "security": "Header-bidding and a sync chain redirect the visitor "
            "into demand partners you cannot enumerate.",
        "resilience": "A US ad-revenue dependency, replaceable but "
            "foreign-controlled.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Amazon Ad System parameter", IMPACT_LOW)
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
