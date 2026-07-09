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

"""LCP/Icordis consent decision-POST detector.

LCP's banner on Icordis-CMS municipal sites is server-rendered HTML —
no JS CMP, no decodable consent cookie. The visitor's choice travels as
a first-party form POST (verified against the rendered www.beernem.be
capture and historical multi-site curl markup):

    <form method="post" action="/cookieverklaring?url=%2f">
      <button name="action" value="decline">Alleen essentiële cookies</button>
      <button name="action" value="acceptall">Alles aanvaarden</button>

The form action is localized per site (``/cookies``,
``/cookieverklaring``); the constant signals are the ``POST`` method, a
path containing ``cookie``, and LCP's own ``action`` values
``acceptall`` / ``decline``. The "Beheer mijn cookies" manage link GETs
the same path and never matches.

This is the consent mechanism itself, not a tracker: the POST goes to
the site's own origin. The decision is decoded by
:func:`leak_inspector.analysis.consent.derive_consent_state`, which
reads the ``action`` value off this module's hits. ``module_name``
deliberately equals
:data:`leak_inspector.analysis.banner_markup.LCP_ICORDIS_BANNER` so the
markup detector (banner presence) and this module (actual decision)
feed one deduplicated name into ``consent.cmp_names``.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_CONSENT,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
    register,
)

#: LCP's own submit-button values — the decision vocabulary.
_DECISION_ACTIONS = frozenset({"acceptall", "decline"})


@register
class LCPIcordisConsentModule(TrackerModule):
    """Detect the LCP/Icordis consent banner's decision POST."""

    module_id = "lcp_icordis_consent"
    # Must equal analysis.banner_markup.LCP_ICORDIS_BANNER (pinned by
    # test) so both detection paths dedupe in consent.cmp_names.
    module_name = "self-hosted consent banner (LCP/Icordis)"
    vendor = "LCP"
    legal_jurisdiction = "BE"
    data_residency = "First-party (self-hosted)"
    sovereignty_notes = (
        "Server-rendered first-party consent banner on the Icordis CMS — "
        "the decision POST goes to the site's own origin; no third-party "
        "data flow."
    )
    # Self-hosted consent banner — the encouraged posture. The decision
    # POST goes to the operator's OWN origin: privacy 0.5 (a first-party
    # consent choice, barely anything leaves), security 0.0 + resilience
    # 0.0 (operator-owned, nothing external to compromise or subpoena).
    impact_rating = ImpactRating(privacy=0.5, security=0.0, resilience=0.0)

    def matches(self, event: RequestEvent) -> bool:
        if event.method.upper() != "POST":
            return False
        if "cookie" not in urlparse(event.url).path.lower():
            return False
        return event.all_params.get("action") in _DECISION_ACTIONS

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            if key == "action":
                category = CAT_CONSENT
                meaning = (
                    "Consent decision (acceptall = accept all cookies, "
                    "decline = essential only)"
                )
            elif key == "url":
                category = CAT_TECHNICAL
                meaning = "Return path after the consent POST"
            elif key == "__RequestVerificationToken":
                category = CAT_TECHNICAL
                meaning = "ASP.NET Core antiforgery (CSRF) token"
            else:
                category = CAT_OTHER
                meaning = "Unrecognized consent-form parameter"
            params.append(
                ParamInfo(
                    key=key,
                    value=value,
                    category=category,
                    meaning=meaning,
                    privacy_impact=IMPACT_LOW,
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