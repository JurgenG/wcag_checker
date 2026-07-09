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

"""EU Cookie Compliance (Drupal GDPR module) detector.

Unlike hosted CMPs (Cookiebot, OneTrust), this is a self-hosted,
first-party consent banner shipped as a Drupal contrib module — very
common on EU public-sector Drupal sites. It has no vendor host, so it
is recognised by its canonical contrib asset path:

    /modules/contrib/eu_cookie_compliance/js/eu_cookie_compliance(.min).js

The banner is loaded from the site's own (first-party) origin. Its
consent decision is persisted in the first-party ``cookie-agreed``
cookie, decoded by :mod:`leak_inspector.analysis.consent`.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    MODULE_KIND_TRACKER,
    ParamInfo,
    TrackerModule,
    register,
)

#: Canonical Drupal contrib path of the module's front-end asset.
_PATH_INFIX = "/modules/contrib/eu_cookie_compliance/"


@register
class EuCookieComplianceModule(TrackerModule):
    """Detect the Drupal EU Cookie Compliance consent banner."""

    module_id = "eu_cookie_compliance"
    module_name = "EU Cookie Compliance (Drupal)"
    vendor = "Drupal community (self-hosted)"
    legal_jurisdiction = ""
    data_residency = "First-party (self-hosted)"
    sovereignty_notes = (
        "Self-hosted Drupal consent banner — no third-party data flow; "
        "the consent decision lives in the first-party cookie-agreed cookie."
    )
    # Not a tracker: it's the consent mechanism itself. The default kind
    # would mislabel a first-party banner as third-party tracking.
    module_kind = MODULE_KIND_TRACKER

    # Self-hosted Drupal consent banner — the encouraged posture; the
    # cookie-agreed decision lives first-party. privacy 0.5 (first-party
    # consent choice), security 0.0 + resilience 0.0 (operator-owned).
    impact_rating = ImpactRating(privacy=0.5, security=0.0, resilience=0.0)

    def matches(self, event: RequestEvent) -> bool:
        return _PATH_INFIX in urlparse(event.url).path

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category = CAT_TECHNICAL if key == "v" else CAT_OTHER
            meaning = (
                "Banner asset version" if key == "v"
                else "Unrecognized EU Cookie Compliance parameter"
            )
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
